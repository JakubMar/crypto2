
#include <iostream>
#include <fstream>
#include <cstring>
#include "enc_dec.h"
///////////
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "mbedtls/cipher.h"
/////////////
using namespace std;


int main2(int argc, char* argv[]){
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
	else {
		cerr << "Wrong mode: \"-e\" - encrypt, \"-d\" - decrypt" << endl;
		return 2;
	}

	FILE* infile; // = fopen(argv[2], "rb");
	fopen_s(&infile, argv[2], "rb");
	if (!infile) {
		cerr << "Cant open file: " << argv[2] << endl;
		return 3;
	}
	FILE* outfile; // = fopen(argv[3], "w");
	fopen_s(&outfile, argv[3], "w");
	if (!outfile) {
		cerr << "Cant open file: " << argv[3] << endl;
		return 3;
	}

	

	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char key[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

	/* encryption */
	if (!mode) {
		if (encryption2(key, iv, infile, outfile)) {
			cerr << "Encryption error" << endl;
		}
	}

	/*decryption*/
	else {
		if (decryption2(key, iv, infile, outfile)) {
			cerr << "Decryption error" << endl;
		}
	}

	fclose(infile);
	fclose(outfile);

	return 0;


return 0;
}


int ma_in(int argc, char* argv[])
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
	//cout << inlen << endl;

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
