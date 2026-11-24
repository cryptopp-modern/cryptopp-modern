// dsa.cpp - originally written and placed in the public domain by Wei Dai

#include <cryptopp/pch.h>

#ifndef CRYPTOPP_IMPORTS

#include <cryptopp/dsa.h>
#include <cryptopp/asn.h>
#include <cryptopp/integer.h>
#include <cryptopp/filters.h>
#include <cryptopp/nbtheory.h>

NAMESPACE_BEGIN(CryptoPP)

size_t DSAConvertSignatureFormat(byte *buffer, size_t bufferSize, DSASignatureFormat toFormat, const byte *signature, size_t signatureLen, DSASignatureFormat fromFormat)
{
	Integer r, s;
	StringStore store(signature, signatureLen);

	switch (fromFormat)
	{
	case DSA_P1363:
		if (signatureLen == 0 || signatureLen % 2 != 0)
			return 0;
		r.Decode(store, signatureLen/2);
		s.Decode(store, signatureLen/2);
		break;
	case DSA_DER:
	{
		BERSequenceDecoder seq(store);
		r.BERDecode(seq);
		s.BERDecode(seq);
		seq.MessageEnd();
		break;
	}
	case DSA_OPENPGP:
		r.OpenPGPDecode(store);
		s.OpenPGPDecode(store);
		break;
	}

	if (r.IsNegative() || s.IsNegative())
		return 0;

	if (toFormat == DSA_P1363)
	{
		if (bufferSize % 2 != 0 || r.MinEncodedSize() > bufferSize/2 || s.MinEncodedSize() > bufferSize/2)
			return 0;
		ArraySink sink(buffer, bufferSize);
		r.Encode(sink, bufferSize/2);
		s.Encode(sink, bufferSize/2);
		return (size_t)sink.TotalPutLength();
	}

	// DER and OpenPGP sizes vary, so encode to a queue and copy only if it fits.
	ByteQueue queue;

	if (toFormat == DSA_DER)
	{
		DERSequenceEncoder seq(queue);
		r.DEREncode(seq);
		s.DEREncode(seq);
		seq.MessageEnd();
	}
	else if (toFormat == DSA_OPENPGP)
	{
		// The MPI header holds a 16-bit bit count.
		if (r.BitCount() > 0xFFFF || s.BitCount() > 0xFFFF)
			return 0;
		r.OpenPGPEncode(queue);
		s.OpenPGPEncode(queue);
	}

	if (queue.CurrentSize() > bufferSize)
		return 0;

	return queue.Get(buffer, bufferSize);
}

NAMESPACE_END

#endif
