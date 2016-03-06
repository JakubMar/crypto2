#pragma once
#include <fstream>

#ifndef _FACT_H_
#define _FACT_H_
int encryption(unsigned char* key, unsigned char* iv, std::ifstream& in_file, size_t in_len, std::ofstream& out_file);

int decryption(unsigned char* key, unsigned char* iv, std::ifstream& in_file, size_t in_len, std::ofstream& out_file);

int encryption2(unsigned char* key, unsigned char* iv, std::FILE* in_file, std::FILE* out_file);

int decryption2(unsigned char* key, unsigned char* iv, std::FILE* in_file, std::FILE* out_file);


#endif