// stateful.cpp - written and placed in the public domain by Colin Brown
//                Framework for stateful signature schemes (SP 800-208)

#include <cryptopp/pch.h>
#include <cryptopp/stateful.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/files.h>
#include <cryptopp/misc.h>

#include <cstring>
#include <limits>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#else
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
# include <errno.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

// ******************** InsecureMemoryStateStore ************************* //

StateReservation InsecureMemoryStateStore::ReserveNext()
{
    if (m_nextIndex >= m_totalLeaves)
        throw SignerExhausted("InsecureMemoryStateStore: signing capacity exhausted");

    return MakeReservation(m_nextIndex++);
}

void InsecureMemoryStateStore::CommitReservation(const StateReservation &reservation)
{
    // In-memory store advances state on reserve, so commit is a no-op.
    // Idempotent by definition: calling twice is harmless.
    CRYPTOPP_UNUSED(reservation);
}

void InsecureMemoryStateStore::AbortReservation(const StateReservation &reservation)
{
    // Abort burns the index. In-memory store already advanced on reserve,
    // so nothing to do. The index is gone.
    CRYPTOPP_UNUSED(reservation);
}

bool InsecureMemoryStateStore::IsExhausted() const
{
    return m_nextIndex >= m_totalLeaves;
}

bool InsecureMemoryStateStore::IsHealthy() const
{
    // This test-only backend does not model integrity failure and
    // therefore always reports healthy. It has no durable state
    // against which to detect rollback or corruption.
    return true;
}

uint64_t InsecureMemoryStateStore::RemainingSignatures() const
{
    // Remaining capacity is simply total minus next index. Aborted
    // reservations do not affect this separately because the index
    // is consumed on reserve, not on commit.
    if (m_nextIndex >= m_totalLeaves)
        return 0;
    return m_totalLeaves - m_nextIndex;
}

// ******************** FileStateStore ************************* //

// File format constants
static const byte FILE_MAGIC[8] = {'C','P','S','S','T','0','0','1'};
static const size_t OFFSET_MAGIC = 0;
static const size_t OFFSET_TOTAL = 8;
static const size_t OFFSET_NEXT  = 16;
static const size_t OFFSET_RESERVED = 24;
static const size_t OFFSET_HMAC  = 32;
static const size_t MUTABLE_OFFSET = 16;  // start of mutable tail
static const size_t MUTABLE_SIZE = 48;    // [16..64)

// Default HMAC key when caller provides none (deterministic checksum only)
static const byte DEFAULT_HMAC_KEY[] = "CryptoPP-FileStateStore-v1";
static const size_t DEFAULT_HMAC_KEY_LEN = sizeof(DEFAULT_HMAC_KEY) - 1;

// ---- Platform file I/O helpers ----

#ifdef _WIN32

// Convert a UTF-8 path to UTF-16 for the Win32 wide-char file APIs.
// MB_ERR_INVALID_CHARS makes malformed UTF-8 a hard error rather than
// silently substituting replacement characters into the resolved path.
static std::wstring Utf8PathToWide(const std::string &path)
{
    if (path.empty()) return std::wstring();
    // MultiByteToWideChar takes the input length as int; the static_cast
    // below would truncate paths above INT_MAX.
    if (path.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: path too long");
    const int wlen = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        path.c_str(), static_cast<int>(path.size()),
        NULLPTR, 0);
    if (wlen <= 0)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: invalid UTF-8 in path: " + path);
    std::wstring wide(static_cast<size_t>(wlen), L'\0');
    const int converted = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        path.c_str(), static_cast<int>(path.size()),
        &wide[0], wlen);
    if (converted != wlen)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: UTF-8 conversion failed for path: " + path);
    return wide;
}

static void* PlatformCreateExclusive(const std::string &path)
{
    const std::wstring wpath = Utf8PathToWide(path);
    HANDLE h = CreateFileW(
        wpath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,  // no sharing
        NULLPTR,
        CREATE_NEW,  // fail if exists
        FILE_ATTRIBUTE_NORMAL,
        NULLPTR);
    if (h == INVALID_HANDLE_VALUE)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: create failed: " + path);
    return h;
}

static void* PlatformOpenExisting(const std::string &path)
{
    const std::wstring wpath = Utf8PathToWide(path);
    HANDLE h = CreateFileW(
        wpath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULLPTR,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULLPTR);
    if (h == INVALID_HANDLE_VALUE)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: cannot open file: " + path);
    return h;
}

static void PlatformWriteAt(void *handle, const byte *data, size_t len, size_t offset)
{
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, li, NULLPTR, FILE_BEGIN))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: seek failed");

    DWORD written = 0;
    if (!WriteFile(handle, data, static_cast<DWORD>(len), &written, NULLPTR) ||
        written != static_cast<DWORD>(len))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: write failed");
}

static void PlatformReadAt(void *handle, byte *data, size_t len, size_t offset)
{
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, li, NULLPTR, FILE_BEGIN))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: seek failed");

    DWORD bytesRead = 0;
    if (!ReadFile(handle, data, static_cast<DWORD>(len), &bytesRead, NULLPTR) ||
        bytesRead != static_cast<DWORD>(len))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: read failed");
}

static void PlatformFlush(void *handle)
{
    if (!FlushFileBuffers(handle))
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: flush failed");
}

static void PlatformClose(void *handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE)
        CloseHandle(handle);
}

#else  // POSIX

static int PlatformCreateExclusive(const std::string &path)
{
    int fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: create failed: " + path);
    return fd;
}

static int PlatformOpenExisting(const std::string &path)
{
    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: cannot open file: " + path);
    return fd;
}

static void PlatformWriteAt(int fd, const byte *data, size_t len, size_t offset)
{
    ssize_t written = pwrite(fd, data, len, static_cast<off_t>(offset));
    if (written < 0 || static_cast<size_t>(written) != len)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: write failed");
}

static void PlatformReadAt(int fd, byte *data, size_t len, size_t offset)
{
    ssize_t bytesRead = pread(fd, data, len, static_cast<off_t>(offset));
    if (bytesRead < 0 || static_cast<size_t>(bytesRead) != len)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: read failed");
}

static void PlatformFlush(int fd)
{
    // macOS: fsync() only flushes to the drive's write cache, not to
    // platter. F_FULLFSYNC is the stronger durability guarantee.
    // For a stateful signing counter, we use the strongest available.
#ifdef __APPLE__
    if (fcntl(fd, F_FULLFSYNC) != 0)
    {
        // F_FULLFSYNC failed - fall back to fsync rather than silently
        // accepting weaker durability. If fsync also fails, throw.
        if (fsync(fd) != 0)
            throw Exception(Exception::IO_ERROR,
                "FileStateStore: flush failed");
    }
#else
    if (fsync(fd) != 0)
        throw Exception(Exception::IO_ERROR,
            "FileStateStore: flush failed");
#endif
}

static void PlatformClose(int fd)
{
    if (fd >= 0)
        close(fd);
}

#endif  // _WIN32

// ---- HMAC helper ----

static void ComputeHMAC(byte *out, const byte *header, size_t headerLen,
                         const byte *key, size_t keyLen)
{
    HMAC<SHA256> hmac(key, keyLen);
    hmac.Update(header, headerLen);
    hmac.Final(out);
}

// ---- Little-endian helpers ----

static void PutLE64(byte *out, uint64_t val)
{
    for (unsigned int i = 0; i < 8; i++)
    {
        out[i] = static_cast<byte>(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t GetLE64(const byte *in)
{
    uint64_t val = 0;
    for (unsigned int i = 0; i < 8; i++)
        val |= static_cast<uint64_t>(in[i]) << (i * 8);
    return val;
}

// ---- FileStateStore implementation ----

FileStateStore::FileStateStore()
    : m_totalLeaves(0), m_nextIndex(0), m_poisoned(false)
#ifdef _WIN32
    , m_handle(INVALID_HANDLE_VALUE)
#else
    , m_fd(-1)
#endif
{
}

FileStateStore::~FileStateStore()
{
#ifdef _WIN32
    PlatformClose(m_handle);
    m_handle = INVALID_HANDLE_VALUE;
#else
    PlatformClose(m_fd);
    m_fd = -1;
#endif
}

FileStateStore::FileStateStore(FileStateStore &&other) noexcept
    : m_path(std::move(other.m_path)),
      m_totalLeaves(other.m_totalLeaves),
      m_nextIndex(other.m_nextIndex),
      m_integrityKey(std::move(other.m_integrityKey)),
      m_poisoned(other.m_poisoned)
#ifdef _WIN32
    , m_handle(other.m_handle)
#else
    , m_fd(other.m_fd)
#endif
{
#ifdef _WIN32
    other.m_handle = INVALID_HANDLE_VALUE;
#else
    other.m_fd = -1;
#endif
    other.m_poisoned = true;  // source is no longer usable
}

FileStateStore &FileStateStore::operator=(FileStateStore &&other) noexcept
{
    if (this != &other)
    {
#ifdef _WIN32
        PlatformClose(m_handle);
        m_handle = other.m_handle;
        other.m_handle = INVALID_HANDLE_VALUE;
#else
        PlatformClose(m_fd);
        m_fd = other.m_fd;
        other.m_fd = -1;
#endif
        m_path = std::move(other.m_path);
        m_totalLeaves = other.m_totalLeaves;
        m_nextIndex = other.m_nextIndex;
        m_integrityKey = std::move(other.m_integrityKey);
        m_poisoned = other.m_poisoned;
        other.m_poisoned = true;
    }
    return *this;
}

void FileStateStore::Poison(const std::string &reason) const
{
    m_poisoned = true;
    throw SignerStateIntegrityFailure("FileStateStore: " + reason);
}

void FileStateStore::WriteState()
{
    // Build the mutable tail [16..64): nextIndex(8) + reserved(8) + HMAC(32)
    byte fileBuf[FILE_SIZE];

    // Reconstruct full header for HMAC computation
    std::memcpy(fileBuf + OFFSET_MAGIC, FILE_MAGIC, 8);
    PutLE64(fileBuf + OFFSET_TOTAL, m_totalLeaves);
    PutLE64(fileBuf + OFFSET_NEXT, m_nextIndex);
    std::memset(fileBuf + OFFSET_RESERVED, 0, 8);

    // Compute HMAC over [0..32)
    const byte *key = m_integrityKey.size() > 0 ? m_integrityKey.begin() : DEFAULT_HMAC_KEY;
    size_t keyLen = m_integrityKey.size() > 0 ? m_integrityKey.size() : DEFAULT_HMAC_KEY_LEN;
    ComputeHMAC(fileBuf + OFFSET_HMAC, fileBuf, OFFSET_HMAC, key, keyLen);

    // Single positioned write of [16..64)
#ifdef _WIN32
    PlatformWriteAt(m_handle, fileBuf + MUTABLE_OFFSET, MUTABLE_SIZE, MUTABLE_OFFSET);
    PlatformFlush(m_handle);
#else
    PlatformWriteAt(m_fd, fileBuf + MUTABLE_OFFSET, MUTABLE_SIZE, MUTABLE_OFFSET);
    PlatformFlush(m_fd);
#endif
}

void FileStateStore::ReadAndVerify() const
{
    byte fileBuf[FILE_SIZE];

#ifdef _WIN32
    PlatformReadAt(m_handle, fileBuf, FILE_SIZE, 0);
#else
    PlatformReadAt(m_fd, fileBuf, FILE_SIZE, 0);
#endif

    // Verify magic
    if (std::memcmp(fileBuf + OFFSET_MAGIC, FILE_MAGIC, 8) != 0)
        Poison("invalid magic number");

    uint64_t fileTotalLeaves = GetLE64(fileBuf + OFFSET_TOTAL);
    uint64_t fileNextIndex = GetLE64(fileBuf + OFFSET_NEXT);

    // Verify reserved field is zero
    byte zeroBlock[8] = {};
    if (std::memcmp(fileBuf + OFFSET_RESERVED, zeroBlock, 8) != 0)
        Poison("reserved field is non-zero");

    // Verify HMAC
    const byte *key = m_integrityKey.size() > 0 ? m_integrityKey.begin() : DEFAULT_HMAC_KEY;
    size_t keyLen = m_integrityKey.size() > 0 ? m_integrityKey.size() : DEFAULT_HMAC_KEY_LEN;
    byte expectedHmac[32];
    ComputeHMAC(expectedHmac, fileBuf, OFFSET_HMAC, key, keyLen);

    if (!VerifyBufsEqual(fileBuf + OFFSET_HMAC, expectedHmac, 32))
        Poison("HMAC verification failed");

    // Verify bounds
    if (fileNextIndex > fileTotalLeaves)
        Poison("nextIndex exceeds totalLeaves");

    if (fileTotalLeaves != m_totalLeaves)
        Poison("totalLeaves mismatch (expected " +
               std::to_string(m_totalLeaves) + ", got " +
               std::to_string(fileTotalLeaves) + ")");

    // Verify no rollback within this process
    if (fileNextIndex < m_nextIndex)
        Poison("on-disk nextIndex is behind in-memory state (possible rollback)");

    // Update cached state
    m_nextIndex = fileNextIndex;
}

FileStateStore FileStateStore::Create(const std::string &path,
                                       uint64_t totalLeaves,
                                       const byte *integrityKey,
                                       size_t keyLen)
{
    FileStateStore store;
    store.m_path = path;
    store.m_totalLeaves = totalLeaves;
    store.m_nextIndex = 0;

    if (integrityKey && keyLen > 0)
        store.m_integrityKey.Assign(integrityKey, keyLen);

#ifdef _WIN32
    store.m_handle = PlatformCreateExclusive(path);
#else
    store.m_fd = PlatformCreateExclusive(path);
#endif

    // Write the full initial file
    byte fileBuf[FILE_SIZE];
    std::memcpy(fileBuf + OFFSET_MAGIC, FILE_MAGIC, 8);
    PutLE64(fileBuf + OFFSET_TOTAL, totalLeaves);
    PutLE64(fileBuf + OFFSET_NEXT, 0);
    std::memset(fileBuf + OFFSET_RESERVED, 0, 8);

    const byte *key = store.m_integrityKey.size() > 0
        ? store.m_integrityKey.begin() : DEFAULT_HMAC_KEY;
    size_t kLen = store.m_integrityKey.size() > 0
        ? store.m_integrityKey.size() : DEFAULT_HMAC_KEY_LEN;
    ComputeHMAC(fileBuf + OFFSET_HMAC, fileBuf, OFFSET_HMAC, key, kLen);

#ifdef _WIN32
    PlatformWriteAt(store.m_handle, fileBuf, FILE_SIZE, 0);
    PlatformFlush(store.m_handle);
#else
    PlatformWriteAt(store.m_fd, fileBuf, FILE_SIZE, 0);
    PlatformFlush(store.m_fd);
#endif

    return store;
}

FileStateStore FileStateStore::Open(const std::string &path,
                                     uint64_t expectedTotalLeaves,
                                     const byte *integrityKey,
                                     size_t keyLen)
{
    FileStateStore store;
    store.m_path = path;
    store.m_totalLeaves = expectedTotalLeaves;
    store.m_nextIndex = 0;

    if (integrityKey && keyLen > 0)
        store.m_integrityKey.Assign(integrityKey, keyLen);

#ifdef _WIN32
    store.m_handle = PlatformOpenExisting(path);
#else
    store.m_fd = PlatformOpenExisting(path);
#endif

    // Read and verify the full file
    store.ReadAndVerify();

    return store;
}

StateReservation FileStateStore::ReserveNext()
{
    if (m_poisoned)
        throw SignerStateIntegrityFailure(
            "FileStateStore: store is poisoned, cannot reserve");

    if (m_nextIndex >= m_totalLeaves)
        throw SignerExhausted("FileStateStore: signing capacity exhausted");

    uint64_t reservedIndex = m_nextIndex;
    m_nextIndex++;

    // Write-ahead: advance on disk before returning reservation
    try {
        WriteState();
    } catch (...) {
        // I/O failure during write - poison the store
        m_poisoned = true;
        throw;
    }

    return MakeReservation(reservedIndex);
}

void FileStateStore::CommitReservation(const StateReservation &reservation)
{
    CRYPTOPP_UNUSED(reservation);
    // Write-ahead store: state already advanced on reserve.
}

void FileStateStore::AbortReservation(const StateReservation &reservation)
{
    CRYPTOPP_UNUSED(reservation);
    // Write-ahead store: state already advanced on reserve. Index is burned.
}

bool FileStateStore::IsExhausted() const
{
    if (m_poisoned)
        return true;
    return m_nextIndex >= m_totalLeaves;
}

bool FileStateStore::IsHealthy() const
{
    if (m_poisoned)
        throw SignerStateIntegrityFailure(
            "FileStateStore: store is poisoned");

    // Re-read and verify. Throws and poisons on failure.
    ReadAndVerify();
    return true;
}

uint64_t FileStateStore::RemainingSignatures() const
{
    if (m_poisoned || m_nextIndex >= m_totalLeaves)
        return 0;
    return m_totalLeaves - m_nextIndex;
}

NAMESPACE_END
