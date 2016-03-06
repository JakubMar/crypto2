

#include "enc_dec.h"
#include <iostream>

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Enc/dec testing", "[basic]") {
	FILE* init, *middle, *output;
	unsigned char str[48] = { "Ultimate perfectly looking string" };
	unsigned char str2[48];
	unsigned char str3[48];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 33, init);
	rewind(init);

	unsigned char key[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char iv2[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	
	CHECK((encryption(key, iv, init, middle)) == 0);
	rewind(middle);
	CHECK((decryption(key, iv2, middle, output)) == 0);
	rewind(middle);
	rewind(output);
	fread(str3, sizeof(unsigned char), 33, middle);
	fread(str2, sizeof(unsigned char), 33, output);
	fclose(init);
	fclose(middle);
	fclose(output);
	CHECK((memcmp(str, str3, 33)) != 0);
	CHECK((memcmp(str, str2, 33)) == 0);
}

TEST_CASE("Enc/dec testing - different key, input length", "[basic]") {
	FILE* init, *middle, *output;
	unsigned char str[16] = { "MARVIN" };
	unsigned char str2[16];
	unsigned char str3[16];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 6, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv2[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	
	CHECK((encryption(key, iv, init, middle)) == 0);
	rewind(middle);
	CHECK((decryption(key, iv2, middle, output)) == 0);
	rewind(middle);
	rewind(output);
	fread(str3, sizeof(unsigned char), 6, middle);
	fread(str2, sizeof(unsigned char), 6, output);
	fclose(init);
	fclose(middle);
	fclose(output);
	CHECK((memcmp(str, str3, 6)) != 0);
	CHECK((memcmp(str, str2, 6)) == 0);
}

TEST_CASE("wrong decryption key", "[key]") {
	FILE* init, *middle, *output;
	unsigned char str[16] = { "0123456789" };
	unsigned char str2[16];
	unsigned char str3[16];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 10, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char key2[16] = { 'f', 'e', 'd','c','b','a','9','8','7','6','5','4','3','2','1','0' };
	unsigned char iv[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x9d, 0xbd, 0xb1, 0x10, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
	unsigned char iv2[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x9d, 0xbd, 0xb1, 0x10, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

	CHECK((encryption(key, iv, init, middle)) == 0);
	rewind(middle);
	CHECK((decryption(key2, iv2, middle, output)) == 0);
	rewind(middle);
	rewind(output);
	fread(str3, sizeof(unsigned char), 10, middle);
	fread(str2, sizeof(unsigned char), 10, output);
	fclose(init);
	fclose(middle);
	fclose(output);
	CHECK((memcmp(str, str3, 10)) != 0);
	CHECK((memcmp(str, str2, 10)) != 0);
}

TEST_CASE("test vector encryption", "[known ciphertext]") {
	FILE* init, *middle, *output;
	unsigned char str[16] = { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
	unsigned char str2[16] = { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};
	unsigned char str3[16];
		
	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 16, init);
	rewind(init);

	unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	unsigned char iv[16] = { 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16	};
	unsigned char iv2[16] = { 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16 };

	CHECK((encryption(key, iv, init, middle)) == 0);
	rewind(middle);
	CHECK((decryption(key, iv2, middle, output)) == 0);
	rewind(middle);
	fread(str3, sizeof(unsigned char), 16, middle);
	CHECK((memcmp(str2, str3, 16)) == 0);	

	fclose(init);
	fclose(middle);
	fclose(output);
}

TEST_CASE("Corrupted encrypted file", "[change in ciphertext]") {
	FILE* init, *middle, *output;
	unsigned char str[32] = { "abcdefghijklmnopqrstuvwxyz" };
	unsigned char str2[96];
	unsigned char str3[32];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 26, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv2[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };

	CHECK((encryption(key, iv, init, middle)) == 0);
	rewind(middle);
	fread(str2, sizeof(unsigned char), 96, middle);
	str2[15] = '0';
	rewind(middle);
	fwrite(str2, sizeof(unsigned char), 96, middle);
	rewind(middle);

	CHECK((decryption(key, iv2, middle, output)) != 0);
	rewind(middle);
	rewind(output);
	fread(str3, sizeof(unsigned char), 26, middle);
	fread(str2, sizeof(unsigned char), 26, output);
	fclose(init);
	fclose(middle);
	fclose(output);
	CHECK((memcmp(str, str3, 26)) != 0);
	CHECK((memcmp(str, str2, 26)) != 0);
	str[15] = '0';
	CHECK((memcmp(str, str2, 26)) != 0);
}
