#include "md5.cuh"
#include "defs.cuh"
#include <iostream>
#include <map>
#include <algorithm>

__device__  void md5Step(uint32_t *buffer, uint32_t *input){
    uint32_t AA = buffer[0];
    uint32_t BB = buffer[1];
    uint32_t CC = buffer[2];
    uint32_t DD = buffer[3];

    uint32_t E;

    uint32_t j;

    for (int r = 0; r < 4; r++) // 4 rounds
    {
        for(int i = 0; i < 16; i++){
            switch(r){
                case 0:
                    E = MD5_F(BB, CC, DD);
                    j = i;
                    break;
                case 1:
                    E = MD5_G(BB, CC, DD);
                    j = ((i * 5) + 1) % 16;
                    break;
                case 2:
                    E = MD5_H(BB, CC, DD);
                    j = ((i * 3) + 5) % 16;
                    break;
                default:
                    E = MD5_I(BB, CC, DD);
                    j = (i * 7) % 16;
                    break;
            }

            uint32_t temp = DD;
            DD = CC;
            CC = BB;
            BB = BB + ROTATE_LEFT(AA + E + K[r*16+i] + input[j], R[r*16+i]);
            AA = temp;
        }
    }

    buffer[0] += AA;
    buffer[1] += BB;
    buffer[2] += CC;
    buffer[3] += DD;
}

__device__ void md5Update(MD5 *obj, uint8_t *input_buffer, size_t input_len){
    uint32_t input[16]; // 16*32 = 512 bit chunk
    uint32_t offset = obj->size % 64;
    obj->size += (uint64_t)input_len;

    for(uint32_t i = 0; i < input_len; ++i){
        obj->input[offset++] = (uint8_t)*(input_buffer + i);

        // we got 512 bits
        if(offset % 64 == 0){
            for(uint32_t j = 0; j < 16; ++j){
                // Convert to little-endian
                input[j] = (uint32_t)(obj->input[(j * 4) + 3]) << 24 |
                           (uint32_t)(obj->input[(j * 4) + 2]) << 16 |
                           (uint32_t)(obj->input[(j * 4) + 1]) <<  8 |
                           (uint32_t)(obj->input[(j * 4)]);
            }
            md5Step(obj->buffer, input);
            offset = 0; // reset for next 512 bits
        }
    }
}

__device__  void md5Finalize(MD5 *obj, uint8_t *result){
    uint32_t input[16];
    uint32_t offset = obj->size % 64;
    uint32_t padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

    md5Update(obj, PADDING, padding_length);
    obj->size -= (uint64_t)padding_length; // md5Update updates obj->size with padded length, undo it

    // Last two 32-bit words are the two halves of the size (converted from bytes to bits)
    for(uint32_t j = 0; j < 14; ++j){
        input[j] = (uint32_t)(obj->input[(j * 4) + 3]) << 24 |
                   (uint32_t)(obj->input[(j * 4) + 2]) << 16 |
                   (uint32_t)(obj->input[(j * 4) + 1]) <<  8 |
                   (uint32_t)(obj->input[(j * 4)]);
    }
    input[14] = (uint32_t)(obj->size * 8); // Lower 32 bits of size
    input[15] = (uint32_t)((obj->size * 8) >> 32); // Higher 32 bits of size

    md5Step(obj->buffer, input);

    // Convert from little-endian and move to result
    for(uint32_t i = 0; i < 4; ++i){
        result[(i * 4) + 0] = (uint8_t)((obj->buffer[i] & 0x000000FF));
        result[(i * 4) + 1] = (uint8_t)((obj->buffer[i] & 0x0000FF00) >>  8);
        result[(i * 4) + 2] = (uint8_t)((obj->buffer[i] & 0x00FF0000) >> 16);
        result[(i * 4) + 3] = (uint8_t)((obj->buffer[i] & 0xFF000000) >> 24);
    }
}

__device__  void to_md5String(char *input, uint8_t *result, size_t input_len){

    MD5 obj;
    
    obj.size = (uint64_t)0;
    obj.buffer[0] = (uint32_t)MD5_A;
    obj.buffer[1] = (uint32_t)MD5_B;
    obj.buffer[2] = (uint32_t)MD5_C;
    obj.buffer[3] = (uint32_t)MD5_D;

    md5Update(&obj, (uint8_t *)input, input_len);
    md5Finalize(&obj, result);
}

__global__ void crack_md5(char* results, size_t input_len, uint64_t total, int* founds, int current_batch) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    
    char pwd[MAX_PWD_SIZE]; // max password length MAX_PWD_SIZE-1 chars
    uint8_t output[16];

    for (uint64_t i = idx; i < total; i+=stride)
    {
        indexToPassword(i, pwd, input_len);
        to_md5String(pwd, output, input_len);

        for (int k = 0; k < current_batch; k++) 
        {
            if (founds[k]) continue; 

            bool match = true;
            for (int j = 0; j < 16; j++) 
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

void md5(std::vector<Job>& jobs)
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

            uint8_t host_hash_buffer[MAX_BATCH_SIZE][16] = {0};
            for (int i = 0; i < current_batch; i++) 
            {
                const std::string& hash_str = pair.second[offset + i];
                for (int j = 0; j < 16; j++) 
                {
                    sscanf(&hash_str[j * 2], "%2hhx", &host_hash_buffer[i][j]); 
                }
            }

            cudaMemcpyToSymbol(target_hash_gpu, host_hash_buffer, current_batch * 16 * sizeof(uint8_t), 0, cudaMemcpyHostToDevice);

            char* passwords_gpu;
            int* found_gpu;
            cudaMalloc(&passwords_gpu, current_batch * MAX_PWD_SIZE);
            cudaMemset(passwords_gpu, 0, current_batch * MAX_PWD_SIZE);
            
            cudaMalloc(&found_gpu, current_batch * sizeof(int));
            cudaMemset(found_gpu, 0, current_batch * sizeof(int));

            int blocks;
            int threads;
            cudaOccupancyMaxPotentialBlockSize(&blocks, &threads, crack_md5, 0, 0);

            crack_md5<<<blocks, threads>>>(passwords_gpu, pair.first, total, found_gpu, current_batch);
            
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