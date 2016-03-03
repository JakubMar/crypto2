
#include <iostream>
#include <fstream>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
using namespace std;

int encryption(unsigned char* key, unsigned char* iv, ifstream& in_file, size_t in_len, ofstream& out_file) {
	mbedtls_cipher_context_t crypt_ctx;
	mbedtls_sha512_context hash_ctx;
	const size_t block = 16;
	size_t out_block = 16;
	unsigned char input[block];
	unsigned char output[block];
	unsigned char hash_output[64];

	mbedtls_sha512_init(&hash_ctx);
	mbedtls_sha512_starts(&hash_ctx, 0);

	mbedtls_cipher_init(&crypt_ctx);
	mbedtls_cipher_setup(&crypt_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&crypt_ctx, MBEDTLS_PADDING_PKCS7);
	mbedtls_cipher_set_iv(&crypt_ctx, iv, 16);
	mbedtls_cipher_setkey(&crypt_ctx, key, 128, MBEDTLS_ENCRYPT);
	for (size_t i = 0; i < in_len; i += block) {
		size_t len = ((in_len - i) > block ? block : (in_len - i));
		in_file.read((char*)input, len);
		mbedtls_cipher_update(&crypt_ctx, input, len, output, &out_block);
		mbedtls_sha512_update(&hash_ctx, output, len);
		out_file.write((char*)output, len);
	}

	mbedtls_sha512_finish(&hash_ctx, hash_output);
	out_file.write((char*)hash_output, 64);

	return 0;
}

int decryption(unsigned char* key, unsigned char* iv, ifstream& in_file, size_t in_len, ofstream& out_file) {
	mbedtls_cipher_context_t crypt_ctx;
	mbedtls_sha512_context hash_ctx;
	
	unsigned char hash_output[64];
	unsigned char given_hash[64];
	const size_t block = 16;
	size_t out_block = 16;
	unsigned char input[block];
	unsigned char output[block];
	
	if ((in_len < 64)){// || (in_len % block != 0)) {
		cerr << "not suitable length of input file" << endl;
		return 1;
	}

	mbedtls_sha512_init(&hash_ctx);
	mbedtls_sha512_starts(&hash_ctx, 0);

	mbedtls_cipher_init(&crypt_ctx);
	mbedtls_cipher_setup(&crypt_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&crypt_ctx, MBEDTLS_PADDING_PKCS7);
	mbedtls_cipher_set_iv(&crypt_ctx, iv, 16);
	mbedtls_cipher_setkey(&crypt_ctx, key, 128, MBEDTLS_DECRYPT);
	

	for (size_t i = 0; i < in_len-65; i += block) {
		int len = (((in_len-65) - i) > block ? block : (int)((in_len-65) - i));
		in_file.read((char*)input, len);
		mbedtls_sha512_update(&hash_ctx, input, len);
		mbedtls_cipher_update(&crypt_ctx, input, len, output, (size_t*)&len);
		out_file.write((char*)output, len);
	}

	mbedtls_sha512_finish(&hash_ctx, hash_output);
	in_file.read((char*)given_hash, 64);
	if (!memcmp(hash_output, given_hash, 64)) {
		cout << "hash ok" << endl;
	}
	else {
		cerr << "different hash" << endl;
		return 2;
	}

	return 0;
}

int main(int argc, char* argv[])
{
	/* parsing arguments */
	if (argc != 4) {
		cerr << "Wrong number of parameters: <-e encryption | -d decryption> <input_file> <output_file>" << endl;
		char c;
		cin >> c;
		return 1;
	}


	int mode;
	if (!strcmp(argv[1], "-e")) {
		mode = 0;
	}
	else if (!strcmp(argv[1], "-d")) {
		mode = 1;
	}
		else{
			cerr << "Wrong mode: \"-e\" - encrypt, \"-d\" - decrypt" << endl;
			return 2;
		}

	ifstream infile(argv[2]);
	if (!infile) {
		cerr << "Cant open file: " << argv[2] << endl;
		return 3;
	}
	ofstream outfile(argv[3]);
	if (!outfile) {
		cerr << "Cant open file: " << argv[3] << endl;
		return 3;
	}

	/* initialization */
	infile.seekg(0, infile.end);
	size_t inlen = static_cast<size_t>(infile.tellg());
	infile.seekg(0, infile.beg);
	cout << inlen << endl;

	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char key[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

	/* encryption */
	if (!mode) {
		if (encryption(key, iv, infile, inlen, outfile)) {
			cerr << "Encryption error" << endl;
		}
	}

	/*decryption*/
	else {
		if (decryption(key, iv, infile, inlen, outfile)) {
			cerr << "Decryption error" << endl;
		}
	}

	infile.close();
	outfile.close();
	return 0;
}