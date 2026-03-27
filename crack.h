#ifndef CRACK_H
#define CRACK_H

#include <stdint.h>
#include <string.h>

#define MAX_PWD_SIZE 8

void md5(char* target_hash, size_t input_len);
void sha1(char* target_hash, size_t input_len);

#endif