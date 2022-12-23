#ifndef BUSINESS_H_
#define BUSINESS_H_

#include <stdint.h>

#define CLA 0x80
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN_SSH_BLOB 0x04
#define INS_SIGN_GENERIC_HASH 0x06
#define INS_SIGN_DIRECT_HASH 0x08
#define INS_GET_ECDH_SECRET 0x0A
#define P1_FIRST 0x00
#define P1_NEXT 0x01
#define P1_LAST_MARKER 0x80
#define P2_PRIME256 0x01
#define P2_CURVE25519 0x02
#define P2_PUBLIC_KEY_MARKER 0x80

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define DEPTH_REQUEST_1 0
#define DEPTH_REQUEST_2 3
#define DEPTH_USER 1

// A path contains 10 elements max, which max length in ascii is 1 whitespace + 10 char + optional quote "'" + "/" + \0"
#define MAX_DERIV_PATH_ASCII_LENGTH 1 + 10*(10+2) + 1


void ins_get_ecdh_secret(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength);
void ins_get_public_key(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength);
void ins_sign_ssh_blob(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength);
void ins_sign_generic_hash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength);
void ins_sign_direct_hash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength);


#endif // BUSINESS_H_