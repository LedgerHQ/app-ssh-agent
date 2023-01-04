#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "business.h"
#include "main.h"
#include "os.h"
#include "cx.h"
#include "ssh_ux.h"

static char keyPath[200];

static uint32_t u32be(uint8_t *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
}

static bool is_curve_valid(uint8_t p2)
{
    return (p2 == P2_PRIME256) || (p2 == P2_CURVE25519);
}

static cx_curve_t get_curve(uint8_t p2)
{
    return (p2 == P2_PRIME256 ? CX_CURVE_256R1 : CX_CURVE_Ed25519);
}

// Print a BIP32 path as an ascii string to display on the device screen
// On the Ledger Blue, if the string is longer than 30 char, the string will be split in multiple lines
unsigned char bip32_print_path(uint32_t *bip32Path, unsigned char bip32PathLength, char* out, unsigned char max_out_len) {

    unsigned char i, offset;
    uint32_t current_level;
    bool hardened;

    if (bip32PathLength > MAX_BIP32_PATH) {
        THROW(INVALID_PARAMETER);
    }
    out[0] = ' ';
    offset=1;
    for (i = 0; i < bip32PathLength; i++) {
        current_level = bip32Path[i];
        hardened = (bool)(current_level & 0x80000000);
        if(hardened) {
            //remove hardening flag
            current_level ^= 0x80000000;
        }
        snprintf(out+offset, max_out_len-offset, "%u", current_level);
        offset = strnlen(out, max_out_len);
        if(offset >= max_out_len - 2) THROW(EXCEPTION_OVERFLOW);
        if(hardened) out[offset++] = '\'';

        out[offset++] = '/';
        out[offset] = '\0';
    }
    // remove last '/'
    out[offset-1] = '\0';

#if defined(TARGET_BLUE)
    // if the path is longer than 30 char, split the string in multiple strings of length 30
    uint8_t len=strnlen(out, MAX_DERIV_PATH_ASCII_LENGTH);
    uint8_t num_split = len/30;


    for(i = 1; i<= num_split; i++) {
        memmove(out+30*i, out+(30*i-1), len-29*i);
        out[30*i-1] = '\0';
    }
#endif

    return offset -1;
}

static void check_path(uint8_t **pDataBuffer, uint32_t *pDataLength)
{
    uint8_t *dataBuffer = *pDataBuffer;
    uint32_t dataLength = *pDataLength;
    int i;

    operationContext.pathLength = *dataBuffer;
    dataBuffer++;
    dataLength--;
    if ((operationContext.pathLength < 0x01) ||
        (operationContext.pathLength > MAX_BIP32_PATH)) {
        PRINTF("Invalid path\n");
        THROW(0x6a80);
    }

    for (i = 0; i < operationContext.pathLength; i++) {
        operationContext.bip32Path[i] = u32be(dataBuffer);
        dataBuffer += 4;
        dataLength -= 4;
    }

    *pDataBuffer = dataBuffer;
    *pDataLength = dataLength;
}

void ins_get_public_key(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                               uint32_t dataLength)
{
    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    cx_curve_t curve;

    if ((p1 != 0) || !is_curve_valid(p2)) {
        THROW(0x6B00);
    }

    check_path(&dataBuffer, &dataLength);
    curve = get_curve(p2);

#if CX_APILEVEL >= 5
    if (curve == CX_CURVE_Ed25519) {
#ifdef TARGET_BLUE
        os_perso_derive_node_bip32(CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL);
#else
        os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12);
#endif
    }
    else {
        os_perso_derive_node_bip32(
        curve, operationContext.bip32Path,
        operationContext.pathLength, privateKeyData, NULL);
    }
#else
    os_perso_derive_seed_bip32(operationContext.bip32Path,
                               operationContext.pathLength,
                               privateKeyData, NULL);
#endif
    cx_ecfp_init_private_key(curve, privateKeyData, 32,
                             &privateKey);
#if ((CX_APILEVEL >= 5) && (CX_APILEVEL < 7))
    if (curve == CX_CURVE_Ed25519) {
        cx_ecfp_init_public_key(curve, NULL, 0,
                                &operationContext.publicKey);
        cx_eddsa_get_public_key(&privateKey,
                                &operationContext.publicKey);
    } else {
        cx_ecfp_generate_pair(
            curve, &operationContext.publicKey, &privateKey, 1);
    }
#else
    cx_ecfp_generate_pair(curve, &operationContext.publicKey,
                          &privateKey, 1);
#endif
    memset(&privateKey, 0, sizeof(privateKey));
    memset(privateKeyData, 0, sizeof(privateKeyData));
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    ui_get_public_key();
}

static void copy_message(uint8_t *dataBuffer, uint32_t available)
{
    if ((operationContext.messageLength + available) > MAX_MSG) {
        THROW(0x6a80);
    }
    memmove(operationContext.message + operationContext.messageLength,
               dataBuffer, available);
    operationContext.messageLength += available;
}

static void read_length(uint8_t *dataBuffer, uint32_t dataLength, uint8_t available)
{
    (void) dataLength;

    memmove(operationContext.lengthBuffer + operationContext.lengthOffset,
               dataBuffer, available);

    operationContext.lengthOffset += available;
    if (operationContext.lengthOffset == 4) {
        operationContext.lengthOffset = 0;
        operationContext.readingElement = true;
        operationContext.elementLength = u32be(operationContext.lengthBuffer);
        // Fixups
        if ((operationContext.depth == DEPTH_REQUEST_1) ||
            (operationContext.depth == DEPTH_REQUEST_2)) {
            operationContext.elementLength++;
        }
    }
}

static void read_user_name(uint8_t *dataBuffer, uint32_t dataLength)
{
    uint32_t userAvailable;

    if (operationContext.userOffset + dataLength > MAX_USER_NAME) {
        userAvailable = MAX_USER_NAME - operationContext.userOffset;
    }
    else {
        userAvailable = dataLength;
    }

    memmove(operationContext.userName + operationContext.userOffset,
               dataBuffer, userAvailable);
    operationContext.userOffset += userAvailable;
}

static void read_element(uint8_t *dataBuffer, uint32_t dataLength, uint32_t available)
{
    if ((operationContext.depth == DEPTH_USER) &&
        (operationContext.userOffset < MAX_USER_NAME)) {
        read_user_name(dataBuffer, dataLength);
    }

    operationContext.elementLength -= available;
    if (operationContext.elementLength == 0) {
        operationContext.readingElement = false;
        operationContext.depth++;
    }
}

static void read_blob(uint8_t **pDataBuffer, uint32_t *pDataLength, bool have_length)
{
    uint8_t *dataBuffer = *pDataBuffer;
    uint32_t dataLength = *pDataLength;
    uint32_t available;

    if (!have_length) {
        available = (uint8_t)MIN(dataLength, 4 - operationContext.lengthOffset);
    }
    else {
        available = MIN(dataLength, operationContext.elementLength);
    }

    if (!operationContext.fullMessageHash) {
        cx_hash(&operationContext.hash.header, 0, dataBuffer, available, NULL, 0);
    } else {
        copy_message(dataBuffer, available);
    }

    if (!have_length) {
        read_length(dataBuffer, dataLength, available);
    }
    else {
        read_element(dataBuffer, dataLength, available);
    }

    dataBuffer += available;
    dataLength -= available;

    *pDataBuffer = dataBuffer;
    *pDataLength = dataLength;
}

void ins_sign_ssh_blob(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength)
{
    bool getPublicKey = ((p2 & P2_PUBLIC_KEY_MARKER) != 0);
    p2 &= ~P2_PUBLIC_KEY_MARKER;

    if (!is_curve_valid(p2)) {
        THROW(0x6B00);
    }

    if (p1 == P1_FIRST) {
        check_path(&dataBuffer, &dataLength);
        operationContext.fullMessageHash =
            (p2 == P2_CURVE25519);
        operationContext.getPublicKey = getPublicKey;
        operationContext.messageLength = 0;
        if (!operationContext.fullMessageHash) {
            cx_sha256_init(&operationContext.hash);
        }
        operationContext.depth = 0;
        operationContext.readingElement = false;
        operationContext.lengthOffset = 0;
        operationContext.userOffset = 0;
        operationContext.direct = false;
    } else if (p1 != P1_NEXT) {
        THROW(0x6B00);
    }

    while (dataLength != 0) {
        if (operationContext.depth >= DEPTH_LAST) {
            THROW(0x6a80);
        }
        if (!operationContext.readingElement) {
            read_blob(&dataBuffer, &dataLength, false);
        }
        if (operationContext.readingElement) {
            read_blob(&dataBuffer, &dataLength, true);
        }
    }

    if (operationContext.depth != DEPTH_LAST) {
        THROW(0x9000);
    }

    if (operationContext.readingElement) {
        THROW(0x6a80);
    }

    operationContext.curve = get_curve(p2);
    operationContext.userName[operationContext.userOffset] =
        '\0';
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    ui_sign_ssh_blob();
}

void ins_sign_generic_hash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength)
{
    bool last = ((p1 & P1_LAST_MARKER) != 0);
    p1 &= ~P1_LAST_MARKER;

    if (!is_curve_valid(p2)) {
        THROW(0x6B00);
    }

    if (p1 == P1_FIRST) {
        check_path(&dataBuffer, &dataLength);
        cx_sha256_init(&operationContext.hash);
        operationContext.direct = false;
        operationContext.getPublicKey = false;
        operationContext.fullMessageHash = false;
    } else if (p1 != P1_NEXT) {
        THROW(0x6B00);
    }

    cx_hash(&operationContext.hash.header, 0, dataBuffer,
            dataLength, NULL, 0);

    if (!last) {
        THROW(0x9000);
    }

    operationContext.curve = get_curve(p2);
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    ui_sign_generic_hash();
}

void ins_sign_direct_hash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint32_t dataLength)
{
    if ((p1 != 0) || !is_curve_valid(p2)) {
        THROW(0x6B00);
    }

    check_path(&dataBuffer, &dataLength);
    if (dataLength != 32) {
        THROW(0x6700);
    }
    operationContext.direct = true;
    operationContext.getPublicKey = false;
    operationContext.curve = get_curve(p2);
    memmove(operationContext.hashData, dataBuffer, 32);

    ui_sign_direct_hash();
}

void ins_get_ecdh_secret(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                                uint32_t dataLength)
{
    if ((p1 != 0x00) || !is_curve_valid(p2)) {
        THROW(0x6B00);
    }

    check_path(&dataBuffer, &dataLength);
    if (dataLength != 65) {
        THROW(0x6700);
    }
    operationContext.curve = get_curve(p2);
    cx_ecfp_init_public_key(operationContext.curve, dataBuffer,
                            65, &operationContext.publicKey);
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    ui_get_ecdh_secret();
}
