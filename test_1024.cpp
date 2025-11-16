// Test 1024 bytes
#include "blake3.h"
#include "hex.h"
#include <iostream>
#include <vector>

using namespace CryptoPP;

int main()
{
	// Generate 1024 bytes of the repeating pattern
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

	std::cout << "1024 byte test:" << std::endl;
	std::cout << "Got:      " << encoded << std::endl;
	std::cout << "Expected: 42214739F095A406F3FC83DEB889744AC00DF831C10DAA55189B5D121C855AF7" << std::endl;
	std::cout << (encoded == "42214739F095A406F3FC83DEB889744AC00DF831C10DAA55189B5D121C855AF7" ? "PASS" : "FAIL") << std::endl;

	return 0;
}
