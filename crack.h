#ifndef CRACK_H
#define CRACK_H

#include <stdint.h>
#include <string>
#include <vector>

#define MAX_PWD_SIZE 8
#define MAX_BATCH_SIZE 1024
#define MAX_PWD_SIZE_DICT 16

struct Job {
    std::string hash;
    int input_len;
};

void md5(std::vector<Job>& jobs);
void sha1(std::vector<Job>& jobs);
void md5_dict(std::vector<std::string>& passwords, std::vector<std::string>& hashes);
void sha1_dict(std::vector<std::string>& passwords, std::vector<std::string>& hashes);

#endif