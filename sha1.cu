#include "sha1.cuh"
#include "defs.cuh"
#include <iostream>

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

__global__ void crack_sha1(uint32_t* input, char* result, size_t input_len, uint64_t total, int* found){

    extern __shared__ uint32_t target_hash[];

    if (threadIdx.x < 5)
    {
        target_hash[threadIdx.x] = input[threadIdx.x];
    }

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;

    __syncthreads();
    
    char pwd[MAX_PWD_SIZE]; // max password length MAX_PWD_SIZE-1 chars
    uint32_t output[5];

    for (uint64_t i = idx; i < total; i+=stride)
    {
        if (*found) return;

        indexToPassword(i, pwd, input_len);
        to_sha1String(pwd, output,input_len);

        bool match = true;
        for (int j = 0; j < 5; j++) 
        {            
            if (output[j] != target_hash[j]) 
            {
                match = false;
                break;
            }
        }

        if (match) 
        {
            if (!*found)
            {
                *found = 1;
                for (int j = 0; j < input_len; j++)
                   result[j] = pwd[j];
                result[input_len] = '\0';
            }
            return;
        }
    }
}

void sha1(char* hash, size_t input_len)
{
    uint32_t target_hash[5];
    for (int i = 0; i < 5; i++) 
    {
        sscanf(&hash[i * 8], "%8x", &target_hash[i]);
    }

    uint32_t* target_hash_gpu;
    cudaMalloc(&target_hash_gpu, 5*sizeof(uint32_t));
    cudaMemcpy(target_hash_gpu, target_hash, 5*sizeof(uint32_t), cudaMemcpyHostToDevice);

    char* password;
    cudaMalloc(&password, MAX_PWD_SIZE);
    cudaMemset(password, 0, MAX_PWD_SIZE);

    uint64_t total = 1;
    for (int i = 0; i < input_len; i++)
        total*=94;
    
    int* found;
    cudaMalloc(&found, sizeof(int));
    cudaMemset(found, 0, sizeof(int));

    int blocks;
    int threads;
    
    cudaOccupancyMaxPotentialBlockSize(&blocks,&threads,crack_sha1,5*sizeof(unsigned),0);
    std::cout<<"Launch Config: "<<blocks<<" Blocks, "<<threads<<" Threads per Block"<< std::endl;

    crack_sha1<<<blocks,threads,5*sizeof(uint32_t),0>>>(target_hash_gpu,password,input_len,total,found);
    cudaError_t err = cudaGetLastError();
    if(err != cudaSuccess)
    {
        std::cout<<"Error: "<<cudaGetErrorString(err);
    }
    cudaDeviceSynchronize();

    char cracked_password[MAX_PWD_SIZE];
    memset(cracked_password,0,MAX_PWD_SIZE);
    cudaMemcpy(cracked_password,password,MAX_PWD_SIZE,cudaMemcpyDeviceToHost);

    
    err = cudaGetLastError();
    if(err != cudaSuccess)
    {
        std::cout<<"Error: "<<cudaGetErrorString(err);
    }

    std::cout<<"Found: "<<cracked_password<<std::endl;

    cudaFree(target_hash_gpu);
    cudaFree(password);
    cudaFree(found);
}