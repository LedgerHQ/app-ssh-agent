/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"

#include "glyphs.h"

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e);

#define MAX_BIP32_PATH 10
#define MAX_USER_NAME 20

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
#define DEPTH_LAST 6

// A path contains 10 elements max, which max length in ascii is 1 whitespace + 10 char + optional quote "'" + "/" + \0"
#define MAX_DERIV_PATH_ASCII_LENGTH 1 + 10*(10+2) + 1 

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#ifdef HAVE_UX_FLOW
#include "ux.h"
    ux_state_t G_ux;
    bolos_ux_params_t G_ux_params;
#else // HAVE_UX_FLOW
    ux_state_t ux;
#endif // HAVE_UX_FLOW

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

#define MAX_MSG 255

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

char keyPath[200];
operationContext_t operationContext;

#if !defined(HAVE_UX_FLOW)

bagl_element_t const ui_address_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "SSH Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_address_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_address_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Get public key for path:",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 297, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 314, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+30,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 331, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+60,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 348, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+90,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}
};

unsigned int ui_address_blue_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_ssh_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "SSH Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm SSH authentication with key:",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
        {{BAGL_LABEL, 0x00, 0, 297, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 314, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+30,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 331, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+60,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 348, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+90,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}
};

unsigned int ui_approval_ssh_blue_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_pgp_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_sign_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm PGP signature with key:",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
        {{BAGL_LABEL, 0x00, 0, 297, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 314, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+30,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 331, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+60,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 348, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+90,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}
};

unsigned int ui_approval_pgp_blue_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    return 0;
}

// UI to approve or deny the signature proposal
static const bagl_element_t const ui_approval_pgp_ecdh_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_ecdh_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_ecdh_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 87, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm PGP ECDH with key:",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
        {{BAGL_LABEL, 0x00, 0, 297, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 314, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+30,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 331, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+60,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
     {{BAGL_LABEL, 0x00, 0, 348, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_11_16PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)keyPath+90,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}
};

unsigned int
ui_approval_pgp_ecdh_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

// UI displayed when no signature proposal has been received
static const bagl_element_t const ui_idle_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0, BAGL_FILL, 0xf9f9f9,
      0xf9f9f9, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "SSH Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 190, 215, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "Exit",
     0,
     0x37ae99,
     0xF9F9F9,
     io_seproxyhal_touch_exit,
     NULL,
     NULL}

};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "SSH/PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //{{BAGL_LABELINE                       , 0x02,   0,  26, 128,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000,
    //BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  },
    //"Waiting for requests...", 0, 0, 0, NULL, NULL, NULL },

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

const bagl_element_t ui_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "SSH/PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Provide public key?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter);

const bagl_element_t ui_approval_ssh_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "SSH Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Authenticate?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "User",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (char *)operationContext.userName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_approval_ssh_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter);

const bagl_element_t ui_approval_pgp_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Sign?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_approval_pgp_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter);

const bagl_element_t ui_approval_pgp_ecdh_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "PGP Agent",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "ECDH?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int
ui_approval_pgp_ecdh_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);


unsigned int ui_approval_ssh_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        switch (element->component.userid) {
        case 1:
            io_seproxyhal_setup_ticker(2000);
            break;
        case 2:
            io_seproxyhal_setup_ticker(3000);
            break;
        }
        return (ux_step == element->component.userid - 1);
    }
    return 1;
}

#endif

#if defined(HAVE_UX_FLOW)
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_idle_flow_1_step, 
    bn, 
    {
      "Application",
      "is ready",
    });
UX_STEP_NOCB(
    ux_idle_flow_2_step, 
    bn, 
    {
      "Version",
      APPVERSION,
    });
UX_STEP_VALID(
    ux_idle_flow_3_step,
    pb,
    os_sched_exit(-1),
    {
      &C_icon_dashboard,
      "Quit",
    });
const ux_flow_step_t *        const ux_idle_flow [] = {
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
  FLOW_END_STEP,
};

//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_address_flow_1_step, 
    pbb,
    io_seproxyhal_touch_address_ok(NULL),
    {
      &C_icon_validate_14,
      "Provide",
      "public key?"
    });
UX_STEP_VALID(
    ux_address_flow_2_step, 
    pb,
    io_seproxyhal_touch_address_cancel(NULL),
    {
      &C_icon_crossmark,
      "Cancel"
    });

const ux_flow_step_t *        const ux_address_flow [] = {
  &ux_address_flow_1_step,
  &ux_address_flow_2_step,
  FLOW_END_STEP,
};

//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_approval_ssh_flow_1_step, 
    pbb,
    io_seproxyhal_touch_sign_ok(NULL),
    {
        &C_icon_validate_14,
#if defined(TARGET_NANOS)        
      "Allow SSH",
#else      
      "Connect SSH user",
#endif      
      (char *)operationContext.userName
    });
/*UX_STEP_VALID(
    ux_approval_ssh_flow_2_step, 
    pb,
    io_seproxyhal_touch_sign_ok(NULL),
    {
      &C_icon_validate_14,
      "Authenticate?"
    });*/
UX_STEP_VALID(
    ux_approval_ssh_flow_3_step, 
    pb,
    io_seproxyhal_touch_sign_cancel(NULL),
    {
      &C_icon_crossmark,
      "Cancel"
    });

const ux_flow_step_t *        const ux_approval_ssh_flow [] = {
  &ux_approval_ssh_flow_1_step,
  //&ux_approval_ssh_flow_2_step,
  &ux_approval_ssh_flow_3_step,
  FLOW_END_STEP,
};

//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_approval_pgp_flow_1_step, 
    pbb,
    io_seproxyhal_touch_sign_ok(NULL),
    {
      &C_icon_validate_14,
      "PGP Agent",
      "Sign?"
    });
UX_STEP_VALID(
    ux_approval_pgp_flow_2_step, 
    pb,
    io_seproxyhal_touch_sign_cancel(NULL),
    {
      &C_icon_crossmark,
      "Cancel"
    });

const ux_flow_step_t *        const ux_approval_pgp_flow [] = {
  &ux_approval_pgp_flow_1_step,
  &ux_approval_pgp_flow_2_step,
  FLOW_END_STEP,
};

//////////////////////////////////////////////////////////////////////
UX_STEP_VALID(
    ux_approval_pgp_ecdh_flow_1_step, 
    pbb,
    io_seproxyhal_touch_sign_ok(NULL),
    {
      &C_icon_validate_14,
      "PGP Agent",
      "ECDH?"
    });
UX_STEP_VALID(
    ux_approval_pgp_ecdh_flow_2_step, 
    pb,
    io_seproxyhal_touch_sign_cancel(NULL),
    {
      &C_icon_crossmark,
      "Cancel"
    });

const ux_flow_step_t *        const ux_approval_pgp_ecdh_flow [] = {
  &ux_approval_pgp_ecdh_flow_1_step,
  &ux_approval_pgp_ecdh_flow_2_step,
  FLOW_END_STEP,
};

#endif // HAVE_UX_FLOW

uint32_t path_item_to_string(char *dest, uint32_t number) {
    uint32_t offset = 0;
    uint32_t startOffset = 0, destOffset = 0;
    uint8_t i;
    uint8_t tmp[11];
    bool hardened = ((number & 0x80000000) != 0);
    number &= 0x7FFFFFFF;
    uint32_t divIndex = 0x3b9aca00;
    while (divIndex != 0) {
        tmp[offset++] = '0' + ((number / divIndex) % 10);
        divIndex /= 10;
    }
    tmp[offset] = '\0';
    while ((tmp[startOffset] == '0') && (startOffset < offset)) {
        startOffset++;
    }
    if (startOffset == offset) {
        dest[destOffset++] = '0';
    } else {
        for (i = startOffset; i < offset; i++) {
            dest[destOffset++] = tmp[i];
        }
    }
    if (hardened) {
        dest[destOffset++] = '\'';
    }
    dest[destOffset++] = '\0';
    return destOffset;
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
        os_memmove(out+30*i, out+(30*i-1), len-29*i);
        out[30*i-1] = '\0';
    }
#endif

    return offset -1;
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

void ui_idle(void) {
ux_step_count = 0;

#if defined(TARGET_BLUE)
    UX_DISPLAY(ui_idle_blue, NULL);
#elif defined(HAVE_UX_FLOW)
    // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
#elif defined(TARGET_NANOS)
    UX_DISPLAY(ui_idle_nanos, NULL);
#endif
}

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // EXIT
        io_seproxyhal_touch_exit(NULL);
        break;
    }
    return 0;
}

unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e) {
    uint8_t privateKeyData[32];
    uint8_t hash[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    if (!operationContext.direct) {
        if (!operationContext.fullMessageHash) {
            cx_hash(&operationContext.hash.header, CX_LAST, hash, 0, hash);
        }
    } else {
        os_memmove(hash, operationContext.hashData, 32);
    }

#if CX_APILEVEL >= 5
    if (operationContext.curve == CX_CURVE_Ed25519) {
#ifdef TARGET_BLUE
        os_perso_derive_node_bip32(CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL);
#else
        os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12);
#endif
    }
    else {
    os_perso_derive_node_bip32(
        operationContext.curve, operationContext.bip32Path,
        operationContext.pathLength, privateKeyData, NULL);
    }
#else
    os_perso_derive_seed_bip32(operationContext.bip32Path,
                               operationContext.pathLength, privateKeyData,
                               NULL);
#endif
    
    cx_ecfp_init_private_key(operationContext.curve, privateKeyData, 32,
                             &privateKey);
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    if (operationContext.curve == CX_CURVE_Ed25519) {
        if (!operationContext.fullMessageHash) {
#if CX_APILEVEL >= 8
            tx = cx_eddsa_sign(&privateKey, CX_LAST, CX_SHA512, hash,
                               sizeof(hash), NULL, 0, G_io_apdu_buffer, NULL);
#else
            tx = cx_eddsa_sign(&privateKey, NULL, CX_LAST, CX_SHA512, hash,
                               sizeof(hash), G_io_apdu_buffer);
#endif            
        } else {
#if CX_APILEVEL >= 8            
            tx = cx_eddsa_sign(
                &privateKey, CX_LAST, CX_SHA512, operationContext.message,
                operationContext.messageLength, NULL, 0, G_io_apdu_buffer, NULL);
#else        
            tx = cx_eddsa_sign(
                &privateKey, NULL, CX_LAST, CX_SHA512, operationContext.message,
                operationContext.messageLength, G_io_apdu_buffer);
#endif            
        }
    } else {
#if CX_APILEVEL >= 8        
        unsigned int info = 0;
        tx = cx_ecdsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256,
                           hash, sizeof(hash), G_io_apdu_buffer, &info);
        if (info & CX_ECCINFO_PARITY_ODD) {
            G_io_apdu_buffer[0] |= 0x01;
        }
#else        
        tx = cx_ecdsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256,
                           hash, sizeof(hash), G_io_apdu_buffer);
#endif        
    }
    if (operationContext.getPublicKey) {
#if ((CX_APILEVEL >= 5) && (CX_APILEVEL < 7))
        if (operationContext.curve == CX_CURVE_Ed25519) {
            cx_ecfp_init_public_key(operationContext.curve, NULL, 0,
                                    &operationContext.publicKey);
            cx_eddsa_get_public_key(&privateKey, &operationContext.publicKey);
        } else {
            cx_ecfp_generate_pair(operationContext.curve,
                                  &operationContext.publicKey, &privateKey, 1);
        }
#else
        cx_ecfp_generate_pair(operationContext.curve,
                              &operationContext.publicKey, &privateKey, 1);
#endif
        os_memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
        tx += 65;
    }
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e) {
    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    
#if CX_APILEVEL >= 5
    if (operationContext.curve == CX_CURVE_Ed25519) {
#ifdef TARGET_BLUE
        os_perso_derive_node_bip32(CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL);
#else
        os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, operationContext.bip32Path, operationContext.pathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12);
#endif
    }
    else {
        os_perso_derive_node_bip32(
        operationContext.curve, operationContext.bip32Path,
        operationContext.pathLength, privateKeyData, NULL);
    }
#else
    os_perso_derive_seed_bip32(operationContext.bip32Path,
                               operationContext.pathLength, privateKeyData,
                               NULL);
#endif
    cx_ecfp_init_private_key(operationContext.curve, privateKeyData, 32,
                             &privateKey);
    tx = cx_ecdh(&privateKey, CX_ECDH_POINT, operationContext.publicKey.W,
                 G_io_apdu_buffer);
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_approval_ssh_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_sign_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_sign_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int ui_approval_pgp_nanos_button(unsigned int button_mask,
                                          unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_sign_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_sign_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int
ui_approval_pgp_ecdh_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_ecdh_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_ecdh_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = 65;
    os_memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
    tx += 65;
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_address_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_address_ok(NULL);
        break;
    }
    }
    return 0;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

static bool is_curve_valid(uint8_t p2)
{
    return (p2 == P2_PRIME256) || (p2 == P2_CURVE25519);
}

static cx_curve_t get_curve(uint8_t p2)
{
    return (p2 == P2_PRIME256 ? CX_CURVE_256R1 : CX_CURVE_Ed25519);
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
        operationContext.bip32Path[i] =
            (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
            (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
        dataLength -= 4;
    }

    *pDataBuffer = dataBuffer;
    *pDataLength = dataLength;
}

static void ins_get_public_key(void)
{
    uint8_t privateKeyData[32];
    uint32_t i;
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA + 1;
    cx_ecfp_private_key_t privateKey;
    cx_curve_t curve;

    operationContext.pathLength =
        G_io_apdu_buffer[OFFSET_CDATA];
    if ((operationContext.pathLength < 0x01) ||
        (operationContext.pathLength > MAX_BIP32_PATH)) {
        PRINTF("Invalid path\n");
        THROW(0x6a80);
    }

    if ((G_io_apdu_buffer[OFFSET_P1] != 0) ||
        ((G_io_apdu_buffer[OFFSET_P2] != P2_PRIME256) &&
         (G_io_apdu_buffer[OFFSET_P2] != P2_CURVE25519))) {
        THROW(0x6B00);
    }
    for (i = 0; i < operationContext.pathLength; i++) {
        operationContext.bip32Path[i] =
            (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
            (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
    }
    if (G_io_apdu_buffer[OFFSET_P2] == P2_PRIME256) {
        curve = CX_CURVE_256R1;
    } else {
#if 0
        normalize_curve25519(privateKeyData);
#endif
        curve = CX_CURVE_Ed25519;
    }

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
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    #if defined(TARGET_BLUE)
         UX_DISPLAY(ui_address_blue, NULL);
    #elif defined(HAVE_UX_FLOW)
        // reserve a display stack slot if none yet
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_address_flow, NULL);
    #elif defined(TARGET_NANOS)
        UX_DISPLAY(ui_address_nanos, NULL);
    #endif
}

static void copy_message(uint8_t *dataBuffer, uint32_t available)
{
    if ((operationContext.messageLength + available) > MAX_MSG) {
        THROW(0x6a80);
    }
    os_memmove(operationContext.message + operationContext.messageLength,
               dataBuffer, available);
    operationContext.messageLength += available;
}

static void read_stuff(uint8_t **pDataBuffer, uint32_t *pDataLength)
{
    uint8_t *dataBuffer = *pDataBuffer;
    uint32_t dataLength = *pDataLength;

    uint8_t available = MIN(dataLength, 4 - operationContext.lengthOffset);
    os_memmove(operationContext.lengthBuffer +
                   operationContext.lengthOffset,
               dataBuffer, available);
    if (!operationContext.fullMessageHash) {
        cx_hash(&operationContext.hash.header, 0,
                dataBuffer, available, NULL);
    } else {
        copy_message(dataBuffer, available);
    }
    dataBuffer += available;
    dataLength -= available;
    operationContext.lengthOffset += available;
    if (operationContext.lengthOffset == 4) {
        operationContext.lengthOffset = 0;
        operationContext.readingElement = true;
        operationContext.elementLength =
            (operationContext.lengthBuffer[0] << 24) |
            (operationContext.lengthBuffer[1] << 16) |
            (operationContext.lengthBuffer[2] << 8) |
            (operationContext.lengthBuffer[3]);
        // Fixups
        if ((operationContext.depth ==
             DEPTH_REQUEST_1) ||
            (operationContext.depth ==
             DEPTH_REQUEST_2)) {
            operationContext.elementLength++;
        }
    }

    *pDataBuffer = dataBuffer;
    *pDataLength = dataLength;
}

static void read_element(uint8_t **pDataBuffer, uint32_t *pDataLength)
{
    uint8_t *dataBuffer = *pDataBuffer;
    uint32_t dataLength = *pDataLength;

    uint32_t available = MIN(dataLength, operationContext.elementLength);
    if (!operationContext.fullMessageHash) {
        cx_hash(&operationContext.hash.header, 0,
                dataBuffer, available, NULL);
    } else {
        copy_message(dataBuffer, available);
    }
    if ((operationContext.depth == DEPTH_USER) &&
        (operationContext.userOffset < MAX_USER_NAME)) {
        uint32_t userAvailable =
            ((operationContext.userOffset +
              dataLength) > MAX_USER_NAME
                 ? (MAX_USER_NAME -
                    operationContext.userOffset)
                 : dataLength);
        os_memmove(operationContext.userName,
                   dataBuffer, userAvailable);
        operationContext.userOffset += userAvailable;
    }
    dataBuffer += available;
    dataLength -= available;
    operationContext.elementLength -= available;
    if (operationContext.elementLength == 0) {
        operationContext.readingElement = false;
        operationContext.depth++;
    }

    *pDataBuffer = dataBuffer;
    *pDataLength = dataLength;
}

static void ins_sign_ssh_blob(void)
{
    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint32_t dataLength = G_io_apdu_buffer[OFFSET_LC];
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
            read_stuff(&dataBuffer, &dataLength);
        }
        if (operationContext.readingElement) {
            read_element(&dataBuffer, &dataLength);
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

    #if defined(TARGET_BLUE)
        UX_DISPLAY(ui_approval_ssh_blue, NULL);
    #elif defined(HAVE_UX_FLOW)
        // reserve a display stack slot if none yet
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_approval_ssh_flow, NULL);
    #elif defined(TARGET_NANOS)
        ux_step = 0;
        ux_step_count = 2;
        UX_DISPLAY(ui_approval_ssh_nanos, ui_approval_ssh_prepro);
    #endif
}

static void ins_sign_generic_hash(void)
{
    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint32_t dataLength = G_io_apdu_buffer[OFFSET_LC];
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
            dataLength, NULL);

    if (!last) {
        THROW(0x9000);
    }

    operationContext.curve = get_curve(p2);
    bip32_print_path(operationContext.bip32Path, operationContext.pathLength, keyPath, sizeof(keyPath));

    #if defined(TARGET_BLUE)
        UX_DISPLAY(ui_approval_pgp_blue, NULL);
    #elif defined(HAVE_UX_FLOW)
        // reserve a display stack slot if none yet
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_approval_pgp_flow, NULL);
    #elif defined(TARGET_NANOS)
        UX_DISPLAY(ui_approval_pgp_nanos, NULL);
    #endif
}

static void ins_sign_direct_hash(void)
{
    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint32_t dataLength = G_io_apdu_buffer[OFFSET_LC];

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
    os_memmove(operationContext.hashData, dataBuffer, 32);

    #if defined(TARGET_BLUE)
        UX_DISPLAY(ui_approval_pgp_blue, NULL);
    #elif defined(HAVE_UX_FLOW)
        // reserve a display stack slot if none yet
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_approval_pgp_flow, NULL);
    #elif defined(TARGET_NANOS)
        UX_DISPLAY(ui_approval_pgp_nanos, NULL);
    #endif
}

static void ins_get_ecdh_secret(void)
{
    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint32_t dataLength = G_io_apdu_buffer[OFFSET_LC];

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

    #if defined(TARGET_BLUE)
        UX_DISPLAY(ui_approval_pgp_ecdh_blue, NULL);
    #elif defined(HAVE_UX_FLOW)
        // reserve a display stack slot if none yet
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_approval_pgp_ecdh_flow, NULL);
    #elif defined(TARGET_NANOS)
        UX_DISPLAY(ui_approval_pgp_ecdh_nanos, NULL);
    #endif
}

void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {
                case INS_GET_PUBLIC_KEY:
                    ins_get_public_key();
                    flags |= IO_ASYNCH_REPLY;
                    break;

                case INS_SIGN_SSH_BLOB:
                    ins_sign_ssh_blob();
                    flags |= IO_ASYNCH_REPLY;
                    break;

                case INS_SIGN_GENERIC_HASH:
                    ins_sign_generic_hash();
                    flags |= IO_ASYNCH_REPLY;
                    break;

                case INS_SIGN_DIRECT_HASH:
                    ins_sign_direct_hash();
                    flags |= IO_ASYNCH_REPLY;
                    break;

                case INS_GET_ECDH_SECRET:
                    ins_get_ecdh_secret();
                    flags |= IO_ASYNCH_REPLY;
                    break;

                case 0xFF: // return to dashboard
                    os_sched_exit(0);

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

void io_seproxyhal_display(const bagl_element_t *element) {
    return io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

#ifdef HAVE_BLE
    // Make automatically discoverable again when disconnected

    case SEPROXYHAL_TAG_BLE_CONNECTION_EVENT:
        if (G_io_seproxyhal_spi_buffer[3] == 0) {
            // TODO : cleaner reset sequence
            // first disable BLE before turning it off
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            // send BLE power on (default parameters)
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
        }
        break;
#endif

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // don't redisplay if UX not allowed (pin locked in the common bolos
            // ux ?)
            if (ux_step_count && UX_ALLOWED) {
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
            }
        });
        break;

    // unknown events are acknowledged
    default:
        UX_DEFAULT_EVENT();
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }
    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

#ifdef TARGET_NANOX
            // grab the current plane mode setting
            G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // TARGET_NANOX

            USB_power(0);
            USB_power(1);

            ui_idle();

#ifdef HAVE_BLE
            BLE_power(0, NULL);
            BLE_power(1, "Nano X");
#endif // HAVE_BLE

            app_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();
}
