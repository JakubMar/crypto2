#pragma once
#include <fstream>

#ifndef _FACT_H_
#define _FACT_H_
int encryption(unsigned char* key, unsigned char* iv, std::ifstream& in_file, size_t in_len, std::ofstream& out_file);

int decryption(unsigned char* key, unsigned char* iv, std::ifstream& in_file, size_t in_len, std::ofstream& out_file);

#endif