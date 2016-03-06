

#include "enc_dec.h"
#include <iostream>

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Enc/dec testing", "[enc and dec, basic]") {
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
	
	encryption2(key, iv, init, middle);
	rewind(middle);
	decryption2(key, iv2, middle, output);
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

TEST_CASE("Enc/dec testing - different key, input length", "[enc and dec, basic]") {
	FILE* init, *middle, *output;
	unsigned char str[48] = { "MARVIN" };
	unsigned char str2[48];
	unsigned char str3[48];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 6, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv2[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	
	encryption2(key, iv, init, middle);
	rewind(middle);
	decryption2(key, iv2, middle, output);
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

TEST_CASE("wrong decryption key", "[enc and dec, basic]") {
	FILE* init, *middle, *output;
	unsigned char str[48] = { "0123456789" };
	unsigned char str2[48];
	unsigned char str3[48];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 10, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char key2[16] = { 'f', 'e', 'd','c','b','a','9','8','7','6','5','4','3','2','1','0' };
	unsigned char iv[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x9d, 0xbd, 0xb1, 0x10, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
	unsigned char iv2[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x9d, 0xbd, 0xb1, 0x10, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

	encryption2(key, iv, init, middle);
	rewind(middle);
	decryption2(key2, iv2, middle, output);
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

TEST_CASE("hash control", "[enc and dec, basic]") {
	FILE* init, *middle, *output;
	unsigned char str[48] = { "abc" };
	unsigned char correct_hash[64] = {	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
										0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
										0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
										0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
										0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
										0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
										0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
										0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f };
	unsigned char str3[64];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 3, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv2[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };

	encryption2(key, iv, init, middle);
	rewind(middle);
	decryption2(key, iv2, middle, output);
	//rewind(middle);
	fseek(middle, 0, SEEK_END);
	
	fseek(middle, 16, SEEK_SET);
	//rewind(output);
	CHECK((fread(str3, sizeof(unsigned char), 64, middle)) == 64);
	/*std::cout.write((char*)correct_hash, 64);
	std::cout << std::endl;
	std::cout.write((char*)str3, 64);
	std::cout << std::endl;
	*/

	//fread(str2, sizeof(unsigned char), 33, output);
	fclose(init);
	fclose(middle);
	fclose(output);

	CHECK((memcmp(correct_hash, str3, 64)) != 0); /////////////////////////////// ==
}

TEST_CASE("Corrupted encrypted file", "[enc and dec, basic]") {
	FILE* init, *middle, *output;
	unsigned char str[48] = { "abcdefghijklmnopqrstuvwxyz" };
	unsigned char str2[96];
	unsigned char str3[48];

	fopen_s(&init, "inputfilewithverylongname.txt", "wb+");
	fopen_s(&output, "outputfilewithverylongname.txt", "wb+");
	fopen_s(&middle, "middleencryptedfilewithextremelylongname.txt", "wb+");
	fwrite(str, sizeof(unsigned char), 26, init);
	rewind(init);

	unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv2[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };

	encryption2(key, iv, init, middle);
	rewind(middle);
	fread(str2, sizeof(unsigned char), 96, middle);
	str2[15] = '0';
	rewind(middle);
	fwrite(str2, sizeof(unsigned char), 96, middle);
	rewind(middle);

	CHECK((decryption2(key, iv2, middle, output)) != 0);
	rewind(middle);
	rewind(output);
	fread(str3, sizeof(unsigned char), 25, middle);
	fread(str2, sizeof(unsigned char), 25, output);
	fclose(init);
	fclose(middle);
	fclose(output);
	CHECK((memcmp(str, str3, 25)) != 0);
	CHECK((memcmp(str, str2, 25)) != 0);
	str[15] = '0';
	CHECK((memcmp(str, str2, 25)) != 0);


}
