#ifndef _MAIN_H_
#define _MAIN_H_

#include "cx.h"

#define MAX_MSG 255
#define MAX_BIP32_PATH 10
#define MAX_USER_NAME 20

typedef struct operationContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    cx_sha256_t hash;
    cx_ecfp_public_key_t publicKey;
    cx_curve_t curve;
    uint8_t depth;
    bool readingElement;
    bool direct;
    bool fullMessageHash;
    bool getPublicKey;
    uint8_t hashData[32];
    uint8_t lengthBuffer[4];
    uint8_t lengthOffset;
    uint32_t elementLength;
    uint8_t userName[MAX_USER_NAME + 1];
    uint32_t userOffset;
    uint8_t message[MAX_MSG];
    uint32_t messageLength;
} operationContext_t;


extern operationContext_t operationContext;


#endif // _MAIN_H_