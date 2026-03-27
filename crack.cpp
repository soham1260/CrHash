#include "crack.h"
#include <iostream>

int main(int argc, char *argv[])
{
    if(argc < 4)
    {
        std::cout<<"Invalid args"<<std::endl;
        return 0;
    }

    if (strcmp(argv[1],"md5") == 0)
    {
        size_t hash_len = strlen(argv[2]);
        int input_len = atoi(argv[3]);
        
        if (hash_len != 32)
        {
            std::cout<<"Invalid hash size"<<std::endl;
            return 0;
        }
        if (input_len+1 > MAX_PWD_SIZE)
        {
            std::cout<<"Invalid size"<<std::endl;
            return 0;
        }

        md5(argv[2],input_len);
    }
    else if (strcmp(argv[1],"sha1") == 0)
    {
        size_t hash_len = strlen(argv[2]);
        int input_len = atoi(argv[3]);
        
        if (hash_len != 40)
        {
            std::cout<<"Invalid hash size"<<std::endl;
            return 0;
        }
        if (input_len+1 > MAX_PWD_SIZE)
        {
            std::cout<<"Invalid size"<<std::endl;
            return 0;
        }

        sha1(argv[2],input_len);
    }
    else
    {
        std::cout<<"Invalid Algo"<<std::endl;
    }
}
// ./crack.exe md5 7815696ecbf1c96e6894b779456d330e 3
// ./crack.exe sha1 f10e2821bbbea527ea02200352313bc059445190 3
// ./crack md5 b7e9f91e18b6e02cb6206b24b141c792 7