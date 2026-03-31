#include "crack.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>

bool load_passwords(const std::string& filename, std::vector<std::string>& passwords) 
{
    std::ifstream file(filename);
    if (!file.is_open()) 
    {
        std::cout << "Failed to open batch file: " << filename << std::endl;
        return false;
    }
    std::string line;
    int line_no = 0;
    while (std::getline(file, line)) 
    {
        line_no++;
        if (line.empty()) continue;
        if (line.length() > MAX_PWD_SIZE_DICT)
        {
            std::cout << "Invalid password size on line number" << line_no << std::endl;
            continue;
        }
        
        passwords.push_back(line);
    }
    return true;
}

bool load_brute_batch(const std::string& filename, std::vector<Job>& jobs, std::string& algo) 
{
    std::ifstream file(filename);
    if (!file.is_open()) 
    {
        std::cout << "Failed to open batch file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    int line_no=0;
    while (std::getline(file, line)) 
    {
        line_no++;
        if (line.empty()) continue; 
        
        std::istringstream iss(line);
        std::string hash;
        int len;
        
        if (iss >> hash >> len) 
        {
            if ((algo == "md5" && hash.length() != 32) || (algo == "sha1" && hash.length() != 40)) 
            {
                std::cout << "Invalid hash size for " << algo << " on line number " << line_no << std::endl;
                continue;
            }
            jobs.push_back({hash, len});
        }
    }
    return true;
}

bool load_dict_batch(const std::string& filename, std::vector<std::string>& hashes, std::string& algo) 
{
    std::ifstream file(filename);
    if (!file.is_open()) 
    {
        std::cout << "Failed to open batch file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    int line_no=0;
    while (std::getline(file, line)) 
    {
        line_no++;
        if (line.empty()) continue; 
        
        std::istringstream iss(line);
        std::string hash;
        
        if (iss >> hash) 
        {
            if ((algo == "md5" && hash.length() != 32) || (algo == "sha1" && hash.length() != 40)) 
            {
                std::cout << "Invalid hash size for " << algo << " on line number " << line_no << std::endl;
                continue;
            }
            hashes.push_back(hash);
        }
    }
    return true;
}

void print_usage() {
    std::cout << "Usage:\n";
    std::cout << "> Single Brute:  ./crack <algo> <hash> <len>\n";
    std::cout << "> Batch Brute:   ./crack <algo> batch <filename>\n";
    std::cout << "> Single Dict:   ./crack <algo> dict <dict_file> <hash>\n";
    std::cout << "> Batch Dict:    ./crack <algo> dict <dict_file> batch <filename>\n";
}

int main(int argc, char *argv[]) 
{
    if (argc < 4) 
    {
        print_usage();
        return 0;
    }

    std::string algo = argv[1];
    if (algo != "md5" && algo != "sha1") 
    {
        std::cout << "Invalid algorithm. Supported: md5, sha1" << std::endl;
        return 0;
    }

    std::string mode = argv[2];

    if (mode == "batch" && argc == 4) 
    {
        std::vector<Job> jobs;
        if (load_brute_batch(argv[3], jobs, algo)) 
        {
            std::cout << "Successfully loaded " << jobs.size() << " target hashes" << std::endl;
            if (algo == "md5") md5(jobs);
            else sha1(jobs);
            return 0;
        }
        return 0;
    }

    if (mode == "dict" && argc >= 5) 
    {
        std::string dict_file = argv[3];
        std::vector<std::string> passwords;
        
        if (!load_passwords(dict_file, passwords)) return 0;

        std::string type = argv[4];

        if (type == "batch" && argc == 6) 
        {
            std::vector<std::string> hashes;
            if (load_dict_batch(argv[5], hashes, algo)) 
            {
                std::cout << "Successfully loaded " << passwords.size() << " passwords and " << hashes.size() << " target hashes" << std::endl;
                if (algo == "md5") md5_dict(passwords, hashes);
                else sha1_dict(passwords, hashes);
            }
            return 0;
        }

        if (argc == 5) 
        {
            if ((algo == "md5" && type.length() != 32) || (algo == "sha1" && type.length() != 40)) 
            {
                std::cout << "Invalid hash size for " << algo << std::endl;
                return 0;
            }
            
            std::cout << "Successfully loaded " << passwords.size() << " passwords" << std::endl;
            std::vector<std::string> hashes = {type};
            if (algo == "md5") md5_dict(passwords, hashes);
            else sha1_dict(passwords, hashes);
            
            return 0;
        }
    }

    if (mode != "batch" && mode != "dict" && argc == 4) 
    {
        std::string hash = argv[2];
        int input_len = std::atoi(argv[3]);
        
        if ((algo == "md5" && hash.length() != 32) || (algo == "sha1" && hash.length() != 40)) 
        {
            std::cout << "Invalid hash size for " << algo << std::endl;
            return 0;
        }
        if (input_len + 1 > MAX_PWD_SIZE) 
        {
            std::cout << "Invalid size. Max length is " << MAX_PWD_SIZE - 1 << std::endl;
            return 0;
        }

        std::vector<Job> jobs = {{hash, input_len}};
        if (algo == "md5") md5(jobs);
        else sha1(jobs);
        
        return 0;
    }

    std::cout << "Invalid command combination" << std::endl;
    print_usage();
    return 0;
}