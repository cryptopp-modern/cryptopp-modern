// wipe_guard.h - written and placed in the public domain by Colin Brown
//                Scope guard that wipes stack storage on every exit

#ifndef CRYPTOPP_PQC_WIPE_GUARD_H
#define CRYPTOPP_PQC_WIPE_GUARD_H

#include <cryptopp/misc.h>

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(PQC_Internal)

/// \brief Wipes a buffer it does not own when the scope ends
/// \details Declare the guard directly after the buffer, before a secret
///  is written to it. The size is a byte count. Use it for arrays and
///  plain structs only; a SecBlock wipes itself.
class WipeGuard : private NotCopyable
{
public:
    WipeGuard(void *buf, size_t byteCount) CRYPTOPP_NO_THROW
        : m_buf(static_cast<byte*>(buf)), m_size(byteCount) {}

    ~WipeGuard() { SecureWipeBuffer(m_buf, m_size); }

private:
    byte *m_buf;
    size_t m_size;
};

NAMESPACE_END  // PQC_Internal
NAMESPACE_END  // CryptoPP

#endif  // CRYPTOPP_PQC_WIPE_GUARD_H
