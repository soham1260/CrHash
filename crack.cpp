#include "crack.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>

void process_batch(std::string filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "Failed to open batch file: " << filename << std::endl;
        return;
    }

    std::string line;
    std::string expected_algo = "";
    int line_number = 0;
    
    std::vector<Job> job_queue;

    while (std::getline(file, line)) {
        line_number++;
        
        if (line.empty()) continue; 

        std::istringstream iss(line);
        std::string algo, hash;
        int input_len;

        if (!(iss >> algo >> hash >> input_len)) {
            std::cout << "Line " << line_number << ": Parsing error. Skipping." << std::endl;
            continue;
        }

        if (expected_algo.empty()) {
            if (algo == "md5" || algo == "sha1") {
                expected_algo = algo;
                std::cout << "Batch locked to algorithm: " << expected_algo << std::endl;
            } else {
                std::cout << "Line " << line_number << ": Invalid base algorithm (" << algo << "). Aborting batch." << std::endl;
                return;
            }
        }

        if (algo != expected_algo) {
            std::cout << "Line " << line_number << ": Algorithm mismatch. Expected " << expected_algo << " but got " << algo << ". Skipping." << std::endl;
            continue;
        }
        
        job_queue.push_back({algo, hash, input_len});
    }

    file.close();

    std::cout << "Successfully loaded " << job_queue.size() << " target hashes. Beginning batch processing" << std::endl;
    
    if (expected_algo == "md5")
    {
        md5(job_queue);
    }
    else if (expected_algo == "sha1")
    {
        sha1(job_queue);
    }
    
    std::cout << "Batch processing complete." << std::endl;
}

int main(int argc, char *argv[])
{
    if(argc < 3) {
        std::cout << "Usage:" << std::endl;
        std::cout << "  Single: ./crack <algo> <hash> <len>" << std::endl;
        std::cout << "  Batch:  ./crack batch <filename>" << std::endl;
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "batch") == 0) {
        process_batch(argv[2]);
        return 0;
    }

    if(argc == 4) {
        std::string algo = argv[1];
        std::string hash = argv[2];
        int input_len = atoi(argv[3]);
        
        if (algo == "md5") {
            if (hash.length() != 32) {
                std::cout << "Invalid hash size" << std::endl;
                return 0;
            }
            if (input_len + 1 > MAX_PWD_SIZE) {
                std::cout << "Invalid size" << std::endl;
                return 0;
            }
            std::vector<Job> jobs = {{algo, hash, input_len}};
            md5(jobs);
        }
        else if (algo == "sha1") {
            if (hash.length() != 40) {
                std::cout << "Invalid hash size" << std::endl;
                return 0;
            }
            if (input_len + 1 > MAX_PWD_SIZE) {
                std::cout << "Invalid size" << std::endl;
                return 0;
            }
            std::vector<Job> jobs = {{algo, hash, input_len}};
            sha1(jobs);
        }
        else {
            std::cout << "Invalid Algo" << std::endl;
        }
    }
    else {
        std::cout << "Usage:" << std::endl;
        std::cout << "> Single: ./crack <algo> <hash> <len>" << std::endl;
        std::cout << "> Batch:  ./crack batch <filename>" << std::endl;
        return 0;
    }
}