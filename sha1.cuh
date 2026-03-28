#ifndef _SHA1_H
#define _SHA1_H

#include "crack.h"

typedef struct
{
    uint32_t Message_Digest[5]; 

    uint32_t Length_Low;        
    uint32_t Length_High;       

    uint8_t Message_Block[64]; 
    int Message_Block_Index;    

    int Computed;               
    int Corrupted;              
} SHA1;

__constant__ static uint32_t K[] = {
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
};

#define SHA1_A 0x67452301
#define SHA1_B 0xefcdab89
#define SHA1_C 0x98badcfe
#define SHA1_D 0x10325476
#define SHA1_E 0xc3d2e1f0

#define MAX_32 0xFFFFFFFF 
#define MAX_8 0xFF

#define CIRCULAR_SHIFT(N,X) ((((X) << (N)) & 0xFFFFFFFF) | ((X) >> (32-(N))))

__constant__ static uint32_t target_hash_gpu[5];    

#endif
