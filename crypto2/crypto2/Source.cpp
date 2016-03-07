
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdio>
#include "enc_dec.h"
using namespace std;



int main(int argc, char* argv[]){
	/* parsing arguments */
	if (argc != 5) {
		cerr << "Wrong number of parameters: <-e encryption | -d decryption> <input_file> <output_file> <key>" << endl;
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
	if ((infile = fopen(argv[2], "rb")) == NULL){
		cerr << "Can't open file: " << argv[2] << endl;
		return 3;
	}

	if ((outfile = fopen(argv[3], "w")) == NULL){
		cerr << "Cant open file: " << argv[3] << endl;
		return 3;
	}

	unsigned char key[16];
	unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
	if (strlen(argv[4]) != 16) {
		cerr << "key-length is not 16" << endl;
		return 4;
	}
	else memcpy(key, argv[4], 16);


	/* encryption */
	if (!mode) {
		if (encryption(key, iv, infile, outfile)) {
			cerr << "Encryption error" << endl;
		}
		else cout << "Encryption complete" << endl;
	}

	/*decryption*/
	else {
		if (decryption(key, iv, infile, outfile)) {
			cerr << "Decryption error" << endl;
		}
		else cout << "Decryption complete" << endl;
	}
	fclose(infile);
	fclose(outfile);
	return 0;
}

