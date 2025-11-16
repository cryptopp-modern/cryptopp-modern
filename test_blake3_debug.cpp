// Quick debug test for BLAKE3
#include "blake3.h"
#include "hex.h"
#include <iostream>
#include <string>

using namespace CryptoPP;

int main()
{
	// Test "Hello, World!"
	BLAKE3 hash;
	std::string message = "Hello, World!";
	std::string digest;

	hash.Update((const byte*)message.data(), message.size());
	digest.resize(32);
	hash.TruncatedFinal((byte*)digest.data(), 32);

	std::string encoded;
	HexEncoder encoder(new StringSink(encoded));
	encoder.Put((const byte*)digest.data(), digest.size());
	encoder.MessageEnd();

	std::cout << "Message: \"" << message << "\"" << std::endl;
	std::cout << "Length: " << message.size() << " bytes" << std::endl;
	std::cout << "Got:      " << encoded << std::endl;
	std::cout << "Expected: EDE5C0B10F2EC4979C69B52F61E42FF5B413519CE09BE0F14D098DCFE5F6F98D" << std::endl;

	// Test empty string
	BLAKE3 hash2;
	std::string digest2;
	digest2.resize(32);
	hash2.TruncatedFinal((byte*)digest2.data(), 32);

	std::string encoded2;
	HexEncoder encoder2(new StringSink(encoded2));
	encoder2.Put((const byte*)digest2.data(), digest2.size());
	encoder2.MessageEnd();

	std::cout << "\nMessage: (empty)" << std::endl;
	std::cout << "Got:      " << encoded2 << std::endl;
	std::cout << "Expected: AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262" << std::endl;

	// Test "abc"
	BLAKE3 hash3;
	std::string message3 = "abc";
	std::string digest3;

	hash3.Update((const byte*)message3.data(), message3.size());
	digest3.resize(32);
	hash3.TruncatedFinal((byte*)digest3.data(), 32);

	std::string encoded3;
	HexEncoder encoder3(new StringSink(encoded3));
	encoder3.Put((const byte*)digest3.data(), digest3.size());
	encoder3.MessageEnd();

	std::cout << "\nMessage: \"" << message3 << "\"" << std::endl;
	std::cout << "Length: " << message3.size() << " bytes" << std::endl;
	std::cout << "Got:      " << encoded3 << std::endl;
	std::cout << "Expected: 6437B3AC38465133FFB63B75273A8DB548C558465D79DB03FD359C6CD5BD9D85" << std::endl;

	return 0;
}
