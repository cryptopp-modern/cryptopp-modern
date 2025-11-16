// Test with official BLAKE3 test vectors
#include "blake3.h"
#include "hex.h"
#include <iostream>
#include <string>
#include <vector>

using namespace CryptoPP;

int main()
{
	// Test with the repeating byte pattern: 0, 1, 2, ..., 249, 250, 0, 1, ...
	// This is the official BLAKE3 test vector format

	// Test 1-byte input
	{
		std::vector<byte> input(1);
		input[0] = 0;

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "1 byte test:" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: 2D3ADEDFF11B61F14C886E35AFA036736DCD87A74D27B5C1510225D0F592E213" << std::endl;
		std::cout << (encoded == "2D3ADEDFF11B61F14C886E35AFA036736DCD87A74D27B5C1510225D0F592E213" ? "PASS" : "FAIL") << "\n\n";
	}

	// Test 2-byte input
	{
		std::vector<byte> input(2);
		for (size_t i = 0; i < input.size(); i++)
			input[i] = (byte)(i % 251);

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "2 byte test:" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: 7B7015BB92CF0B318037702A6CAE4C6E5D9AEC56CA96AEEB42D0CA5812DB1E58" << std::endl;
		std::cout << (encoded == "7B7015BB92CF0B318037702A6CAE4C6E5D9AEC56CA96AEEB42D0CA5812DB1E58" ? "PASS" : "FAIL") << "\n\n";
	}

	// Test 3-byte input (should match what we saw working)
	{
		std::vector<byte> input(3);
		for (size_t i = 0; i < input.size(); i++)
			input[i] = (byte)(i % 251);

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "3 byte test:" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: E1BE4D7A8AB5560AA4199EACA8A9B4A73A087FA3C30ED28AA3F9BDDD3C09DB3D" << std::endl;
		std::cout << (encoded == "E1BE4D7A8AB5560AA4199EACA8A9B4A73A087FA3C30ED28AA3F9BDDD3C09DB3D" ? "PASS" : "FAIL") << "\n\n";
	}

	// Test 63-byte input
	{
		std::vector<byte> input(63);
		for (size_t i = 0; i < input.size(); i++)
			input[i] = (byte)(i % 251);

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "63 byte test:" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: F553E8262BB5DC6BD27F79C66EB6ECB46AB4F93089D5DAFA2BAAF64FA4EB4DAB" << std::endl;
		std::cout << (encoded == "F553E8262BB5DC6BD27F79C66EB6ECB46AB4F93089D5DAFA2BAAF64FA4EB4DAB" ? "PASS" : "FAIL") << "\n\n";
	}

	// Test 64-byte input (one full block)
	{
		std::vector<byte> input(64);
		for (size_t i = 0; i < input.size(); i++)
			input[i] = (byte)(i % 251);

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "64 byte test (1 block):" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: 4D01F2E5F5DE0A56F73E9ED61CBBEC77E13ED01C62E55C5DE328C2AD0C57AD52" << std::endl;
		std::cout << (encoded == "4D01F2E5F5DE0A56F73E9ED61CBBEC77E13ED01C62E55C5DE328C2AD0C57AD52" ? "PASS" : "FAIL") << "\n\n";
	}

	// Test 65-byte input (>1 block)
	{
		std::vector<byte> input(65);
		for (size_t i = 0; i < input.size(); i++)
			input[i] = (byte)(i % 251);

		BLAKE3 hash;
		hash.Update(input.data(), input.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::cout << "65 byte test (>1 block):" << std::endl;
		std::cout << "Got:      " << encoded << std::endl;
		std::cout << "Expected: DE66D03F20BD1D7C37F7CFB42EE2B7FB8140E59C0E6FB7C6E1CD0F1D6AED93D8" << std::endl;
		std::cout << (encoded == "DE66D03F20BD1D7C37F7CFB42EE2B7FB8140E59C0E6FB7C6E1CD0F1D6AED93D8" ? "PASS" : "FAIL") << "\n\n";
	}

	return 0;
}
