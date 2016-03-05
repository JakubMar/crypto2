#include <iostream>
#include <fstream>
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "enc_dec.h"
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

	if ((in_len < 64)) {// || (in_len % block != 0)) {
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

	size_t len;
	for (size_t i = 0; i < in_len - 65; i += block) {
		len = (((in_len - 65) - i) > block ? block : (in_len - 65) - i);
		in_file.read((char*)input, len);
		mbedtls_sha512_update(&hash_ctx, input, len);
		mbedtls_cipher_update(&crypt_ctx, input, len, output, &len);
		out_file.write((char*)output, len);
	}

	mbedtls_sha512_finish(&hash_ctx, hash_output);
	in_file.read((char*)given_hash, 64);
	/*cout.write((char*)given_hash, 64);
	cout << endl;
	cout.write((char*)given_hash, 64);
	cout << endl;*/
	if (!memcmp(hash_output, given_hash, 64)) {
		cout << "hash ok" << endl;
	}
	else {
		cerr << "different hash" << endl;
		//return 2;
	}
	bool correct = 1;
	for (int i = 0; i < 64; ++i) {
		if (given_hash[i] != hash_output[i]) {
			correct = 0;
			break;
		}
	}
	if (correct)
		cout << "cycle hash ok" << endl;
	else
		cout << "cycle hash nok" << endl;

	return 0;
}