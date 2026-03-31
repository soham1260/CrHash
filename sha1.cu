#include "sha1.cuh"
#include "defs.cuh"
#include <iostream>
#include <map>
#include <algorithm>

__device__ void SHA1ProcessMessageBlock(SHA1 *obj)
{
    int t;                  
    uint32_t temp;               
    uint32_t W[80];              
    uint32_t A, B, C, D, E;      

    for(t = 0; t < 16; t++)
    {
        W[t] = ((uint32_t) obj->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t) obj->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t) obj->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t) obj->Message_Block[t * 4 + 3]);
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = CIRCULAR_SHIFT(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = obj->Message_Digest[0];
    B = obj->Message_Digest[1];
    C = obj->Message_Digest[2];
    D = obj->Message_Digest[3];
    E = obj->Message_Digest[4];

    for(t = 0; t < 20; t++)
    {
        temp = CIRCULAR_SHIFT(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= MAX_32;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = CIRCULAR_SHIFT(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= MAX_32;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = CIRCULAR_SHIFT(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= MAX_32;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = CIRCULAR_SHIFT(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= MAX_32;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    obj->Message_Digest[0] = (obj->Message_Digest[0] + A) & MAX_32;
    obj->Message_Digest[1] = (obj->Message_Digest[1] + B) & MAX_32;
    obj->Message_Digest[2] = (obj->Message_Digest[2] + C) & MAX_32;
    obj->Message_Digest[3] = (obj->Message_Digest[3] + D) & MAX_32;
    obj->Message_Digest[4] = (obj->Message_Digest[4] + E) & MAX_32;

    obj->Message_Block_Index = 0;
}

__device__ void SHA1Input(SHA1 *obj, uint8_t *message_array, uint32_t length)
{
    if (!length)
    {
        return;
    }

    if (obj->Computed || obj->Corrupted)
    {
        obj->Corrupted = 1;
        return;
    }

    while(length-- && !obj->Corrupted)
    {
        obj->Message_Block[obj->Message_Block_Index++] = (*message_array & MAX_8);

        obj->Length_Low += 8;
        // Force it to 32 bits 
        obj->Length_Low &= MAX_32;
        if (obj->Length_Low == 0)
        {
            obj->Length_High++;
            // Force it to 32 bits
            obj->Length_High &= MAX_32;
            if (obj->Length_High == 0)
            {
                // Message is too long 
                obj->Corrupted = 1;
            }
        }

        if (obj->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(obj);
        }

        message_array++;
    }
}

__device__ void SHA1PadMessage(SHA1 *obj)
{
    if (obj->Message_Block_Index > 55)
    {
        obj->Message_Block[obj->Message_Block_Index++] = 0x80;
        while(obj->Message_Block_Index < 64)
        {
            obj->Message_Block[obj->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(obj);

        while(obj->Message_Block_Index < 56)
        {
            obj->Message_Block[obj->Message_Block_Index++] = 0;
        }
    }
    else
    {
        obj->Message_Block[obj->Message_Block_Index++] = 0x80;
        while(obj->Message_Block_Index < 56)
        {
            obj->Message_Block[obj->Message_Block_Index++] = 0;
        }
    }

    obj->Message_Block[56] = (obj->Length_High >> 24) & MAX_8;
    obj->Message_Block[57] = (obj->Length_High >> 16) & MAX_8;
    obj->Message_Block[58] = (obj->Length_High >> 8) & MAX_8;
    obj->Message_Block[59] = (obj->Length_High) & MAX_8;
    obj->Message_Block[60] = (obj->Length_Low >> 24) & MAX_8;
    obj->Message_Block[61] = (obj->Length_Low >> 16) & MAX_8;
    obj->Message_Block[62] = (obj->Length_Low >> 8) & MAX_8;
    obj->Message_Block[63] = (obj->Length_Low) & MAX_8;

    SHA1ProcessMessageBlock(obj);
}

__device__ void to_sha1String(char *input, uint32_t *result, size_t input_len)
{
    SHA1 obj;
    
    obj.Length_Low = 0;
    obj.Length_High = 0;
    obj.Message_Block_Index = 0;

    obj.Message_Digest[0] = SHA1_A;
    obj.Message_Digest[1] = SHA1_B;
    obj.Message_Digest[2] = SHA1_C;
    obj.Message_Digest[3] = SHA1_D;
    obj.Message_Digest[4] = SHA1_E;

    obj.Computed = 0;
    obj.Corrupted = 0;

    SHA1Input(&obj, (uint8_t *) input, input_len);

    if (obj.Corrupted)
    {
        for(int i = 0; i < 5 ; i++)
        {
            result[i] = 0;
        }
        return;
    }

    if (!obj.Computed)
    {
        SHA1PadMessage(&obj);
        obj.Computed = 1;
    }

    for(int i = 0; i < 5 ; i++)
    {
        result[i] = obj.Message_Digest[i];
    }
}

__global__ void crack_sha1(char* results, size_t input_len, uint64_t total, int* founds, int current_batch){

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    char pwd[MAX_PWD_SIZE]; // max password length MAX_PWD_SIZE-1 chars
    uint32_t output[5];

    for (uint64_t i = idx; i < total; i+=stride)
    {
        indexToPassword(i, pwd, input_len);
        to_sha1String(pwd, output,input_len);

        for (int k = 0; k < current_batch; k++)
        {
            if (founds[k]) continue; 

            bool match = true;
            for (int j = 0; j < 5; j++) 
            {            
                if (output[j] != target_hash_gpu[k][j]) 
                {
                    match = false;
                    break;
                }
            }

            if (match) 
            {
                founds[k] = 1;
                int offset = k * MAX_PWD_SIZE;
                for (int j = 0; j < input_len; j++)
                {
                    results[offset + j] = pwd[j];
                }
                results[offset + input_len] = '\0';
            }
        }
    }
}

void sha1(std::vector<Job>& jobs)
{
    std::map<int, std::vector<std::string>> jobs_by_len;
    for (const auto& job : jobs) 
    {
        jobs_by_len[job.input_len].push_back(job.hash);
    }

    for (const auto& pair : jobs_by_len) 
    {
        uint64_t total = 1;
        for (int i = 0; i < pair.first; i++) total *= 94;

        int total_hashes = pair.second.size();

        for (int offset = 0; offset < total_hashes; offset += MAX_BATCH_SIZE) 
        {
            int current_batch = std::min(MAX_BATCH_SIZE, total_hashes - offset);

            uint32_t host_hash_buffer[MAX_BATCH_SIZE][5] = {0};
            for (int i = 0; i < current_batch; i++) 
            {
                const std::string& hash_str = pair.second[offset + i];
                for (int j = 0; j < 5; j++) 
                {
                    sscanf(&hash_str[j * 8], "%8x", &host_hash_buffer[i][j]); 
                }
            }

            cudaMemcpyToSymbol(target_hash_gpu, host_hash_buffer, current_batch * 5 * sizeof(uint32_t), 0, cudaMemcpyHostToDevice);

            char* passwords_gpu;
            int* found_gpu;
            cudaMalloc(&passwords_gpu, current_batch * MAX_PWD_SIZE);
            cudaMemset(passwords_gpu, 0, current_batch * MAX_PWD_SIZE);
            
            cudaMalloc(&found_gpu, current_batch * sizeof(int));
            cudaMemset(found_gpu, 0, current_batch * sizeof(int));

            int blocks;
            int threads;
            cudaOccupancyMaxPotentialBlockSize(&blocks, &threads, crack_sha1, 0, 0);

            crack_sha1<<<blocks*4, threads>>>(passwords_gpu, pair.first, total, found_gpu, current_batch);

            cudaError_t err = cudaGetLastError();
            if(err != cudaSuccess) 
            {
                std::cout << "Kernel Launch Error: " << cudaGetErrorString(err) << std::endl;
            }
            cudaDeviceSynchronize();

            int found_host[MAX_BATCH_SIZE] = {0};
            char passwords_host[MAX_BATCH_SIZE][MAX_PWD_SIZE] = {0};

            cudaMemcpy(found_host, found_gpu, current_batch * sizeof(int), cudaMemcpyDeviceToHost);
            cudaMemcpy(passwords_host, passwords_gpu, current_batch * MAX_PWD_SIZE, cudaMemcpyDeviceToHost);

            for (int i = 0; i < current_batch; i++) 
            {
                if (found_host[i]) 
                {
                    std::cout << "Match found - Hash: " << pair.second[offset + i] << " -> Password: " << passwords_host[i] << std::endl;
                }
            }

            cudaFree(passwords_gpu);
            cudaFree(found_gpu);
        }
    }
}

__device__ int compare_hashes_sha1(const uint32_t* a, const uint32_t* b) {
    for (int i = 0; i < 5; i++) 
    {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

__global__ void crack_sha1_dict(char* passwords, uint32_t* hashes, char* results, int* founds, int total_targets, int dict_size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;

    uint32_t output[5];

    for (int i = idx; i < dict_size; i += stride) 
    {
        char* curr_password = &passwords[i * MAX_PWD_SIZE_DICT];

        int word_len = 0;
        while (word_len < MAX_PWD_SIZE_DICT && curr_password[word_len] != '\0') 
        {
            word_len++;
        }
        if (word_len == 0) continue;

        to_sha1String(curr_password, output, word_len);

        int left = 0;
        int right = total_targets-1;
        int match_index = -1;

        while (left <= right) 
        {
            int mid = left+(right-left)/2;
            int cmp = compare_hashes_sha1(output, &hashes[mid * 5]);

            if (cmp == 0) 
            {
                match_index = mid;
                break;
            }
            if (cmp < 0)
                right = mid-1;
            else
                left = mid+1;
        }

        if (match_index != -1) 
        {
            founds[match_index] = 1;
            int offset = match_index * MAX_PWD_SIZE_DICT;
            for (int j = 0; j < word_len; j++) 
            {
                results[offset + j] = curr_password[j];
            }
            results[offset + word_len] = '\0';
        }
    }
}