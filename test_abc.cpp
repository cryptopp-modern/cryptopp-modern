// Test "abc" which we know passes
#include "blake3.h"
#include "hex.h"
#include <iostream>
#include <string>

using namespace CryptoPP;

int main()
{
	// Test what "abc" actually hashes to
	BLAKE3 hash1;
	std::string message1 = "abc";
	std::string digest1;

	hash1.Update((const byte*)message1.data(), message1.size());
	digest1.resize(32);
	hash1.TruncatedFinal((byte*)digest1.data(), 32);

	std::string encoded1;
	HexEncoder encoder1(new StringSink(encoded1));
	encoder1.Put((const byte*)digest1.data(), digest1.size());
	encoder1.MessageEnd();

	std::cout << "\"abc\" (0x61, 0x62, 0x63):" << std::endl;
	std::cout << "Got: " << encoded1 << std::endl;

	// Now test bytes 0, 1, 2 (which is what the official test vectors use)
	BLAKE3 hash2;
	byte input2[3] = {0, 1, 2};
	std::string digest2;

	hash2.Update(input2, 3);
	digest2.resize(32);
	hash2.TruncatedFinal((byte*)digest2.data(), 32);

	std::string encoded2;
	HexEncoder encoder2(new StringSink(encoded2));
	encoder2.Put((const byte*)digest2.data(), digest2.size());
	encoder2.MessageEnd();

	std::cout << "\nBytes {0, 1, 2}:" << std::endl;
	std::cout << "Got:      " << encoded2 << std::endl;
	std::cout << "Expected: E1BE4D7A8AB5560AA4199EACA8A9B4A73A087FA3C30ED28AA3F9BDDD3C09DB3D" << std::endl;

	return 0;
}
