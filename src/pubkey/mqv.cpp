// mqv.cpp - originally written and placed in the public domain by Wei Dai
//           HMQV provided by Jeffrey Walton, Ray Clayton and Uri Blumenthal.
//           FHMQV provided by Uri Blumenthal.

#include <cryptopp/pch.h>
#include <cryptopp/config.h>
#include <cryptopp/mqv.h>
#include <cryptopp/hmqv.h>
#include <cryptopp/fhmqv.h>
#include <cryptopp/eccrypto.h>

// Squash MS LNK4221 and libtool warnings
extern const char MQV_FNAME[] = __FILE__;

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void TestInstantiations_MQV()
{
    MQV mqv;
    ECMQV<ECP> ecmqv;

    CRYPTOPP_UNUSED(mqv);
    CRYPTOPP_UNUSED(ecmqv);
}

void TestInstantiations_HMQV()
{
    HMQV hmqv;
    ECHMQV<ECP> echmqv;

    CRYPTOPP_UNUSED(hmqv);
    CRYPTOPP_UNUSED(echmqv);
}

void TestInstantiations_FHMQV()
{
    FHMQV fhmqv;
    ECFHMQV<ECP> ecfhmqv;

    CRYPTOPP_UNUSED(fhmqv);
    CRYPTOPP_UNUSED(ecfhmqv);
}
#endif

NAMESPACE_END
