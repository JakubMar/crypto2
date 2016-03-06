#pragma once
#include <fstream>

#ifndef _FACT_H_
#define _FACT_H_
int encryption(unsigned char* key, unsigned char* iv, std::FILE* in_file, std::FILE* out_file);

int decryption(unsigned char* key, unsigned char* iv, std::FILE* in_file, std::FILE* out_file);


#endif