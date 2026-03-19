// stateful.cpp - written and placed in the public domain by Colin Brown
//                Framework for stateful signature schemes (SP 800-208)

#include <cryptopp/pch.h>
#include <cryptopp/stateful.h>

NAMESPACE_BEGIN(CryptoPP)

// ******************** InsecureMemoryStateStore ************************* //

StateReservation InsecureMemoryStateStore::ReserveNext()
{
    if (m_nextIndex >= m_totalLeaves)
        throw SignerExhausted("InsecureMemoryStateStore: signing capacity exhausted");

    return StateReservation(m_nextIndex++);
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

NAMESPACE_END
