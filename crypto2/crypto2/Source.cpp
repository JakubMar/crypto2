
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdio>
#include "enc_dec.h"
using namespace std;


int main(int argc, char* argv[]){
	/* parsing arguments */
	if (argc != 4) {
		cerr << "Wrong number of parameters: <-e encryption | -d decryption> <input_file> <output_file>" << endl;
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

	FILE* infile, *outfile; 
	if (fopen_s(&infile, argv[2], "rb")){
		cerr << "Can't open file: " << argv[2] << endl;
		return 3;
	}

	if (fopen_s(&outfile, argv[3], "w")){
		cerr << "Cant open file: " << argv[3] << endl;
		return 3;
	}

	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	unsigned char key[16] = { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

	/* encryption */
	if (!mode) {
		if (encryption(key, iv, infile, outfile)) {
			cerr << "Encryption error" << endl;
		}
	}

	/*decryption*/
	else {
		if (decryption(key, iv, infile, outfile)) {
			cerr << "Decryption error" << endl;
		}
	}

	fclose(infile);
	fclose(outfile);

	return 0;


return 0;
}

