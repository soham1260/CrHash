#ifndef CRACK_H
#define CRACK_H

#include <stdint.h>
#include <string>
#include <vector>

#define MAX_PWD_SIZE 8
#define MAX_BATCH_SIZE 1024

struct Job {
    std::string algo;
    std::string hash;
    int input_len;
};

void md5(std::vector<Job>& jobs);
void sha1(std::vector<Job>& jobs);

#endif