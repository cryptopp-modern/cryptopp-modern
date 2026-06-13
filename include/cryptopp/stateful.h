// stateful.h - written and placed in the public domain by Colin Brown
//              Framework for stateful signature schemes (SP 800-208)

/// \file stateful.h
/// \brief Framework types for stateful signature schemes
/// \details Stateful hash-based signature schemes such as LMS/HSS and
///  XMSS/XMSSMT differ from stateless schemes in that each signature
///  consumes signer state. Index reuse breaks security.
/// \details Defines the signer interface, persistence backend contract,
///  and reservation token used by stateful signing schemes.
/// \details PK_StatefulSigner is intentionally NOT a subtype of PK_Signer.
///  Stateful signers must not be silently substitutable for stateless signers.
/// \sa <A HREF="https://csrc.nist.gov/pubs/sp/800/208/final">NIST SP 800-208</A>
/// \since cryptopp-modern 2026.6.0

#ifndef CRYPTOPP_STATEFUL_H
#define CRYPTOPP_STATEFUL_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/config_int.h>
#include <cryptopp/secblock.h>

#include <string>

NAMESPACE_BEGIN(CryptoPP)

// ******************** Exceptions ************************* //

/// \brief Thrown when a stateful signer has exhausted its signing capacity
/// \details This is expected eventual behaviour for stateful signature
///  schemes. The signer has used all available one-time signing indices.
class SignerExhausted : public Exception
{
public:
    /// \brief Construct a SignerExhausted
    /// \param s the message for the exception
    explicit SignerExhausted(const std::string &s)
        : Exception(OTHER_ERROR, s) {}
};

/// \brief Thrown when a state backend detects integrity failure
/// \details This indicates the backend cannot safely continue issuing
///  reservations. Possible causes include rollback, corruption, or
///  inconsistency in the stored signing state. Signing must stop until
///  an operator resolves the condition.
class SignerStateIntegrityFailure : public Exception
{
public:
    /// \brief Construct a SignerStateIntegrityFailure
    /// \param s the message for the exception
    explicit SignerStateIntegrityFailure(const std::string &s)
        : Exception(OTHER_ERROR, s) {}
};

// ******************** State Reservation ************************* //

/// \brief Opaque capability representing a claimed signing index
/// \details A StateReservation is a backend-issued, move-only token
///  representing a unique, non-reusable claim on a one-time signing
///  index. Once issued, the index is consumed and must not be reissued,
///  even if the reservation is aborted.
/// \details Callers must not construct, modify, or duplicate this object.
///  It is created by SignerStateStore::ReserveNext() and passed to
///  CommitReservation() or AbortReservation(). The signer should treat
///  it as opaque and should not depend on its internal representation.
class StateReservation
{
public:
    /// \brief Returns the reserved signing index
    /// \details For single-tree schemes (LMS) this is a leaf index.
    ///  For hierarchical schemes (HSS) this is a global signing index
    ///  that the signer decomposes into per-level leaf indices.
    ///  The signer should use this value as the reserved signing index.
    uint64_t LeafIndex() const { return m_leafIndex; }

    /// \brief Move constructor
    StateReservation(StateReservation &&other) noexcept
        : m_leafIndex(other.m_leafIndex), m_valid(other.m_valid)
    {
        other.m_leafIndex = 0;
        other.m_valid = false;
    }

    /// \brief Move assignment
    StateReservation &operator=(StateReservation &&other) noexcept
    {
        if (this != &other)
        {
            m_leafIndex = other.m_leafIndex;
            m_valid = other.m_valid;
            other.m_leafIndex = 0;
            other.m_valid = false;
        }
        return *this;
    }

    ~StateReservation() = default;

    // Non-copyable
    StateReservation(const StateReservation &) = delete;
    StateReservation &operator=(const StateReservation &) = delete;

    /// \brief Check whether this reservation still represents a valid claim
    /// \details Returns false after move. Backends must reject invalid
    ///  reservations passed to CommitReservation() or AbortReservation()
    ///  with SignerStateIntegrityFailure.
    bool IsValid() const { return m_valid; }

private:
    // All state store backends construct reservations through this friendship.
    friend class SignerStateStore;

    explicit StateReservation(uint64_t leafIndex)
        : m_leafIndex(leafIndex), m_valid(true) {}

    uint64_t m_leafIndex;
    bool m_valid;
};

// ******************** State Store ************************* //

/// \brief Abstract state backend for stateful signing schemes
/// \details SignerStateStore provides the persistence contract for
///  stateful signature schemes. Implementations must satisfy one
///  normative security invariant:
/// \details <b>For any given private signing state, the backend must
///  ensure that no reserved one-time signing index is ever made
///  available for reuse, even after crashes, aborts, or interrupted
///  operations.</b>
/// \details Safe failure means loss of capacity (burned indices).
///  Unsafe failure means index reuse. The entire persistence model
///  flows from this distinction.
class SignerStateStore
{
public:
    virtual ~SignerStateStore() = default;

protected:
    /// \brief Factory method for constructing StateReservation objects
    /// \details Only state store backends should construct reservations.
    ///  This protected factory avoids friending every concrete backend.
    static StateReservation MakeReservation(uint64_t leafIndex)
    {
        return StateReservation(leafIndex);
    }

public:

    /// \brief Reserve the next available signing index
    /// \return a move-only StateReservation by value
    /// \throw SignerExhausted if no indices remain
    /// \throw SignerStateIntegrityFailure if the backend cannot
    ///  guarantee its invariants
    virtual StateReservation ReserveNext() = 0;

    /// \brief Durably commit a reservation after successful signing
    /// \param reservation the reservation to commit
    /// \details Must be idempotent: a second commit of the same valid
    ///  reservation must succeed without advancing state.
    /// \throw SignerStateIntegrityFailure if the reservation is invalid
    virtual void CommitReservation(const StateReservation &reservation) = 0;

    /// \brief Abort a reservation
    /// \param reservation the reservation to abort
    /// \details The reserved index is burned and must not be made
    ///  available for reuse. Abort does not cancel consumption.
    /// \throw SignerStateIntegrityFailure if the reservation is invalid
    virtual void AbortReservation(const StateReservation &reservation) = 0;

    /// \brief Check if signing capacity is exhausted
    /// \return true if no signing indices remain
    virtual bool IsExhausted() const = 0;

    /// \brief Verify backend integrity
    /// \return true if the backend is healthy
    /// \throw SignerStateIntegrityFailure if integrity cannot be trusted;
    ///  the backend enters a poisoned state and subsequent ReserveNext()
    ///  and IsHealthy() calls also throw
    /// \details This is not a passive boolean probe. Implementations
    ///  must signal detected rollback, corruption, or inconsistency by
    ///  throwing, not by returning false.
    virtual bool IsHealthy() const = 0;

    /// \brief Returns the current view of remaining signing capacity
    /// \return number of remaining signatures
    /// \details Implementations must never overcount. Undercounting is
    ///  acceptable when indices have been burned by aborted reservations
    ///  or when the backend cannot safely determine exact capacity.
    ///  Callers should treat this as a planning signal, not an absolute
    ///  guarantee.
    virtual uint64_t RemainingSignatures() const = 0;
};

// ******************** Stateful Signer ************************* //

/// \brief Base class for stateful signature schemes
/// \details PK_StatefulSigner provides the signing interface for schemes
///  where each signature consumes signer state. SignMessage() is non-const
///  because signing mutates logical state.
/// \details PK_StatefulSigner is intentionally NOT a subtype of PK_Signer.
///  There is no shared base class or adaptor that makes them polymorphically
///  interchangeable. If a future need arises for code that works with both,
///  the correct path is an explicit adaptor or distinct generic interface,
///  not inheritance from PK_Signer.
class PK_StatefulSigner
{
public:
    virtual ~PK_StatefulSigner() = default;

    /// \brief Returns the algorithm name
    virtual std::string AlgorithmName() const = 0;

    /// \brief Returns the exact signature size
    /// \return signature size in bytes for the current key and parameter set
    virtual size_t SignatureLength() const = 0;

    /// \brief Check if signing capacity is exhausted
    /// \return true if no signing indices remain
    virtual bool IsExhausted() const = 0;

    /// \brief Returns the current view of remaining signing capacity
    /// \return number of remaining signatures
    /// \details Implementations must never overcount. Undercounting is
    ///  acceptable when indices have been burned by aborted reservations
    ///  or when the backend cannot safely determine exact capacity.
    ///  Callers should treat this as a planning signal, not an absolute
    ///  guarantee.
    virtual uint64_t RemainingSignatures() const = 0;

    /// \brief Sign a message
    /// \param rng a RandomNumberGenerator
    /// \param message pointer to the message to sign
    /// \param messageLen length of the message in bytes
    /// \param signature pointer to output buffer of exactly SignatureLength() bytes
    /// \details This is a non-const operation that consumes one signing
    ///  index. Internally this performs: reserve, sign, commit. On
    ///  signing failure, the reserved index is burned.
    /// \throw SignerExhausted if no signing capacity remains
    /// \throw SignerStateIntegrityFailure if the state backend cannot
    ///  guarantee its invariants
    virtual void SignMessage(
        RandomNumberGenerator &rng,
        const byte *message, size_t messageLen,
        byte *signature) = 0;
};

// ******************** Test-Only State Store ************************* //

/// \brief In-memory state store for testing and KAT validation only
/// \details InsecureMemoryStateStore provides a trivial in-memory
///  implementation of SignerStateStore suitable for unit tests, KAT
///  validation, and developer experimentation.
/// \details NOT safe for production use. Does not survive process
///  termination. Does not protect against duplication, rollback,
///  or multi-process access.
class InsecureMemoryStateStore : public SignerStateStore
{
public:
    /// \brief Construct a test-only state store
    /// \param totalLeaves the total number of available signing indices (must be > 0)
    /// \throw InvalidArgument if totalLeaves is zero
    explicit InsecureMemoryStateStore(uint64_t totalLeaves)
        : m_nextIndex(0), m_totalLeaves(totalLeaves)
    {
        if (totalLeaves == 0)
            throw InvalidArgument("InsecureMemoryStateStore: totalLeaves must be greater than zero");
    }

    StateReservation ReserveNext() override;
    void CommitReservation(const StateReservation &reservation) override;
    void AbortReservation(const StateReservation &reservation) override;
    bool IsExhausted() const override;
    bool IsHealthy() const override;
    uint64_t RemainingSignatures() const override;

private:
    uint64_t m_nextIndex;
    uint64_t m_totalLeaves;
};

// ******************** File-Backed State Store ************************* //

/// \brief File-backed durable state store for stateful signing schemes
/// \details Write-ahead persistence for the signing index counter.
///  The index advances on disk before the reservation is returned.
///  On crash, at most one index is lost. No index is ever reused.
///  Single-writer only - concurrent writers cause index reuse.
///  Targets desktop/server platforms with POSIX or Win32 filesystems.
///  Embedded targets should implement SignerStateStore directly.
/// \sa SignerStateStore, InsecureMemoryStateStore
/// \since cryptopp-modern 2026.6.0
class FileStateStore : public SignerStateStore
{
public:
    /// \brief File format size in bytes
    static const size_t FILE_SIZE = 64;

    /// \brief Create a new state file
    /// \param path filesystem path for the state file
    /// \param totalLeaves total signing capacity
    /// \param integrityKey optional HMAC key for corruption detection (may be null)
    /// \param keyLen length of integrity key in bytes (0 if no key)
    /// \details Throws if file already exists. Silent overwrite is not
    ///  supported because it risks destroying valid signing state.
    /// \throw Exception with IO_ERROR if file already exists or cannot be created
    static FileStateStore Create(const std::string &path,
                                  uint64_t totalLeaves,
                                  const byte *integrityKey = NULLPTR,
                                  size_t keyLen = 0);

    /// \brief Open an existing state file
    /// \param path filesystem path for the state file
    /// \param expectedTotalLeaves expected signing capacity (must match file)
    /// \param integrityKey optional HMAC key (must match key used at creation)
    /// \param keyLen length of integrity key in bytes
    /// \throw SignerStateIntegrityFailure on any verification failure
    ///  (magic, HMAC, capacity mismatch, bounds violation, reserved non-zero)
    static FileStateStore Open(const std::string &path,
                                uint64_t expectedTotalLeaves,
                                const byte *integrityKey = NULLPTR,
                                size_t keyLen = 0);

    ~FileStateStore();

    // Non-copyable
    FileStateStore(const FileStateStore &) = delete;
    FileStateStore &operator=(const FileStateStore &) = delete;

    /// \brief Move constructor (transfers file handle ownership)
    /// \details Moving transfers the single-writer role. It does not
    ///  make concurrent use safe.
    FileStateStore(FileStateStore &&other) noexcept;
    FileStateStore &operator=(FileStateStore &&other) noexcept;

    /// \brief Reserve the next signing index (write-ahead)
    /// \details Advances nextIndex on disk via a single positioned write
    ///  of the mutable tail [16..64), then fsync, before returning.
    ///  If the process crashes between the write and return, one index
    ///  is lost. That is safe capacity loss, not index reuse.
    /// \throw SignerExhausted if no indices remain
    /// \throw SignerStateIntegrityFailure if the store is poisoned
    StateReservation ReserveNext() override;

    /// \brief Validate and commit a reservation
    /// \details State was already advanced on reserve, so valid commits do
    ///  not perform additional persistence work.
    /// \throw SignerStateIntegrityFailure if the reservation is invalid
    void CommitReservation(const StateReservation &reservation) override;

    /// \brief Validate and burn a reservation
    /// \details State was already advanced on reserve, so valid aborts do
    ///  not roll back. The reserved index is burned and is not reused.
    /// \throw SignerStateIntegrityFailure if the reservation is invalid
    void AbortReservation(const StateReservation &reservation) override;

    bool IsExhausted() const override;

    /// \brief Re-read from disk and verify integrity
    /// \details Re-reads the file, verifies all fields, and refreshes
    ///  the in-memory cache. If any check fails, the store is poisoned.
    /// \throw SignerStateIntegrityFailure on any verification failure
    ///  or if the store is already poisoned
    bool IsHealthy() const override;

    uint64_t RemainingSignatures() const override;

private:
    FileStateStore();

    void WriteState();
    void ReadAndVerify() const;
    void Poison(const std::string &reason) const;

    std::string m_path;
    uint64_t m_totalLeaves;
    mutable uint64_t m_nextIndex;
    SecByteBlock m_integrityKey;
    mutable bool m_poisoned;

#ifdef _WIN32
    void *m_handle;
#else
    int m_fd;
#endif
};

NAMESPACE_END

#endif  // CRYPTOPP_STATEFUL_H
