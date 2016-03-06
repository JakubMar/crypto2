

#include "enc_dec.h"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

TEST_CASE("Enc/dec testing", "[enc and dec, basic]") {
	FILE* init;
	fopen_s(&init, "asdfghjklqwert.txt", "wb+");
	unsigned char str[40] = { "Ultimate perfectly looking string" };
	unsigned char str2[40];
	fwrite(str, sizeof(unsigned char), 33, init);
	//fclose(init);
	//FILE* input;
	//fopen_s(&input, "asdfghjklqwert.txt", "rb");
	FILE* output;
	fopen_s(&output, "outputasdfghjklqwert.txt", "wb+");
	FILE* middle;
	fopen_s(&middle, "middlesdfghjklqwert.txt", "wb+");
	rewind(init);
	//unsigned char key[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	//unsigned char iv[16] = { '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0' };
	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char key[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
	encryption2(key, iv, init, middle);
	unsigned char iv2[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char key2[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
	//fclose(middle);
	//fopen_s(&middle, "middlesdfghjklqwert.txt", "rb");	
	rewind(middle);
	decryption2(key2, iv2, middle, output);
	fclose(init);
	fclose(middle);
	//fclose(output);

	//fopen_s(&output, "outputasdfghjklqwert.txt", "rb");
	rewind(output);
	fread(str2, sizeof(unsigned char), 33, output);
	fclose(output);
    CHECK((memcmp(str, str2, 33)) == 0);
    
}
