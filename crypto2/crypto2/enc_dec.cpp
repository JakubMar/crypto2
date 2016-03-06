#include <iostream>
#include <fstream>
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
#include "enc_dec.h"
#include <cstdio>
using namespace std;

int encryption(unsigned char* key, unsigned char* iv, FILE* in_file, FILE* out_file) {
	mbedtls_cipher_context_t crypt_ctx;
	mbedtls_sha512_context hash_ctx;
	const size_t block = 16;
	size_t out_block = 16;
	unsigned char input[block];
	unsigned char output[block];
	unsigned char hash_output[64];

	fseek(in_file, 0, SEEK_END);
	size_t in_len = static_cast<size_t>(ftell(in_file));
	rewind(in_file);

	mbedtls_sha512_init(&hash_ctx);
	mbedtls_sha512_starts(&hash_ctx, 0);

	mbedtls_cipher_init(&crypt_ctx);
	mbedtls_cipher_setup(&crypt_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC));
	mbedtls_cipher_set_padding_mode(&crypt_ctx, MBEDTLS_PADDING_PKCS7);
	mbedtls_cipher_set_iv(&crypt_ctx, iv, 16);
	mbedtls_cipher_setkey(&crypt_ctx, key, 128, MBEDTLS_ENCRYPT);
	for (size_t i = 0; i < in_len; i += block) {
		size_t len = ((in_len - i) > block ? block : (in_len - i));
		if ((fread(input, sizeof(unsigned char), len, in_file)) != len) {
			cerr << "reading error" << endl;
			return 1;
		}
		mbedtls_cipher_update(&crypt_ctx, input, len, output, &out_block);
		mbedtls_sha512_update(&hash_ctx, output, out_block);
		if ((fwrite(output, sizeof(unsigned char), out_block, out_file)) != out_block) {
			cerr << "writing error" << endl;
			return 2;
		}
	}

	mbedtls_cipher_finish(&crypt_ctx, output, &out_block);
	mbedtls_sha512_update(&hash_ctx, output, out_block);
	if((fwrite(output, sizeof(unsigned char), out_block, out_file)) != out_block){
		cerr << "writing error" << endl;
		return 2;
	}
	mbedtls_sha512_finish(&hash_ctx, hash_output);
	if((fwrite(hash_output, sizeof(unsigned char), 64, out_file)) != 64) {
		cerr << "writing error" << endl;
		return 2;
	}
	return 0;
}

int decryption(unsigned char* key, unsigned char* iv, FILE* in_file, FILE* out_file) {
	mbedtls_cipher_context_t crypt_ctx;
	mbedtls_sha512_context hash_ctx;
	const size_t block = 16;
	size_t out_block = 16;
	unsigned char hash_output[64];
	unsigned char given_hash[64];	
	unsigned char input[block];
	unsigned char output[block];

	fseek(in_file, 0, SEEK_END);
	size_t in_len = static_cast<size_t>(ftell(in_file));
	rewind(in_file);

	if ((in_len < 64) || (in_len % block != 0)) {
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

	for (size_t i = 0; i < in_len - 64; i += block) {
		size_t len = (((in_len - 64) - i) >= block ? block : (in_len - 64) - i);
		if ((fread(input, sizeof(unsigned char), len, in_file)) != len) {
			cerr << "reading error" << endl;
			return 2;
		}
		mbedtls_sha512_update(&hash_ctx, input, len);
		mbedtls_cipher_update(&crypt_ctx, input, len, output, &out_block);
		if ((fwrite(output, sizeof(unsigned char), out_block, out_file)) != out_block){
			cerr << "writing error" << endl;
			return 3;
		}
	}
	mbedtls_cipher_finish(&crypt_ctx, output, &out_block);
	fwrite(output, sizeof(unsigned char), out_block, out_file);
	mbedtls_sha512_finish(&hash_ctx, hash_output);
	if ((fread(given_hash, sizeof(unsigned char), 64, in_file)) != 64) {
		cerr << "reading error" << endl;
		return 2;
	}

	if (!memcmp(hash_output, given_hash, 64)) {
		cout << "hash ok" << endl;
	}
	else {
		cerr << "different hash" << endl;
		return 4;
	}
	return 0;
}