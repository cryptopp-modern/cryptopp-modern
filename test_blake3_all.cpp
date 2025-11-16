// Comprehensive BLAKE3 test
#include "blake3.h"
#include "hex.h"
#include "files.h"
#include <iostream>
#include <vector>

using namespace CryptoPP;

int main()
{
	int passed = 0, failed = 0;

	// Test 1: Empty string
	{
		BLAKE3 hash;
		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::string expected = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
		if (encoded == expected) {
			std::cout << "PASSED: Empty string\n";
			passed++;
		} else {
			std::cout << "FAILED: Empty string\n";
			std::cout << "  Got:      " << encoded << "\n";
			std::cout << "  Expected: " << expected << "\n";
			failed++;
		}
	}

	// Test 2: "abc"
	{
		BLAKE3 hash;
		std::string message = "abc";
		hash.Update((const byte*)message.data(), message.size());

		std::string digest;
		digest.resize(32);
		hash.TruncatedFinal((byte*)digest.data(), 32);

		std::string encoded;
		HexEncoder encoder(new StringSink(encoded));
		encoder.Put((const byte*)digest.data(), digest.size());
		encoder.MessageEnd();

		std::string expected = "6437B3AC38465133FFB63B75273A8DB548C558465D79DB03FD359C6CD5BD9D85";
		if (encoded == expected) {
			std::cout << "PASSED: \"abc\"\n";
			passed++;
		} else {
			std::cout << "FAILED: \"abc\"\n";
			std::cout << "  Got:      " << encoded << "\n";
			std::cout << "  Expected: " << expected << "\n";
			failed++;
		}
	}

	// Test 3: 1024 bytes
	{
		std::vector<byte> input(1024);
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

		std::string expected = "42214739F095A406F3FC83DEB889744AC00DF831C10DAA55189B5D121C855AF7";
		if (encoded == expected) {
			std::cout << "PASSED: 1024 bytes\n";
			passed++;
		} else {
			std::cout << "FAILED: 1024 bytes\n";
			std::cout << "  Got:      " << encoded << "\n";
			std::cout << "  Expected: " << expected << "\n";
			failed++;
		}
	}

	// Test 4: 2048 bytes
	{
		std::vector<byte> input(2048);
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

		std::string expected = "E776B6028C7CD22A4D0BA182A8BF62205D2EF576467E838ED6F2529B85FBA24A";
		if (encoded == expected) {
			std::cout << "PASSED: 2048 bytes\n";
			passed++;
		} else {
			std::cout << "FAILED: 2048 bytes\n";
			std::cout << "  Got:      " << encoded << "\n";
			std::cout << "  Expected: " << expected << "\n";
			failed++;
		}
	}

	// Test 5: 4096 bytes
	{
		std::vector<byte> input(4096);
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

		std::string expected = "015094013F57A5277B59D8475C0501042C0B642E531B0A1C8F58D2163229E969";
		if (encoded == expected) {
			std::cout << "PASSED: 4096 bytes\n";
			passed++;
		} else {
			std::cout << "FAILED: 4096 bytes\n";
			std::cout << "  Got:      " << encoded << "\n";
			std::cout << "  Expected: " << expected << "\n";
			failed++;
		}
	}

	std::cout << "\n========================================\n";
	std::cout << "BLAKE3 Test Results:\n";
	std::cout << "  Passed: " << passed << "\n";
	std::cout << "  Failed: " << failed << "\n";
	std::cout << "========================================\n";

	return (failed == 0) ? 0 : 1;
}
