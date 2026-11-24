// dsa.h - originally written and placed in the public domain by Wei Dai

/// \file dsa.h
/// \brief Classes for the DSA signature algorithm

#ifndef CRYPTOPP_DSA_H
#define CRYPTOPP_DSA_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/gfpcrypt.h>

NAMESPACE_BEGIN(CryptoPP)

/// \brief DSA Signature Format
/// \details The DSA signature format used by Crypto++ is as defined by IEEE P1363.
///  OpenSSL, Java and .Net use the DER format, and OpenPGP uses the OpenPGP format.
/// \sa <A HREF="http://www.cryptopp.com/wiki/DSAConvertSignatureFormat">DSAConvertSignatureFormat</A>
///  on the Crypto++ wiki.
/// \since Crypto++ 1.0
enum DSASignatureFormat {
	/// \brief Crypto++ native signature encoding format
	DSA_P1363,
	/// \brief signature encoding format used by OpenSSL, Java and .Net
	DSA_DER,
	/// \brief OpenPGP signature encoding format
	DSA_OPENPGP
};

/// \brief Converts between signature encoding formats
/// \param buffer byte buffer for the converted signature encoding
/// \param bufferSize the length of the converted signature encoding buffer
/// \param toFormat the source signature format
/// \param signature byte buffer for the existing signature encoding
/// \param signatureLen the length of the existing signature encoding buffer
/// \param fromFormat the source signature format
/// \return the number of bytes written during encoding, or 0 if the signature
///  cannot be converted
/// \details This function converts between these formats, and returns length
///  of signature in the target format. If <tt>toFormat == DSA_P1363</tt>, then
///  <tt>bufferSize</tt> must equal <tt>publicKey.SignatureLength()</tt> or
///  <tt>verifier.SignatureLength()</tt>.
/// \details The function returns 0 and leaves <tt>buffer</tt> unchanged if the
///  destination buffer is too small, if <tt>r</tt> or <tt>s</tt> is negative
///  or does not fit the target format, or if a P1363 signature or buffer has
///  an empty or odd length. Check the return value before using the buffer.
///  Malformed DER or OpenPGP input throws <tt>BERDecodeErr</tt> or
///  <tt>OpenPGPDecodeErr</tt>.
/// \details The function checks that <tt>r</tt> and <tt>s</tt> can be
///  represented in the target format.
/// \details Zero-valued components are preserved. The verifier checks
///  whether <tt>r</tt> and <tt>s</tt> are in range for the key.
/// \sa <A HREF="http://www.cryptopp.com/wiki/DSAConvertSignatureFormat">DSAConvertSignatureFormat</A>
///  on the Crypto++ wiki.
/// \since Crypto++ 1.0
size_t DSAConvertSignatureFormat(byte *buffer, size_t bufferSize, DSASignatureFormat toFormat,
	const byte *signature, size_t signatureLen, DSASignatureFormat fromFormat);

NAMESPACE_END

#endif  // CRYPTOPP_DSA_H
