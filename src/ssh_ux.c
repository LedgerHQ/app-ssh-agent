
#include "ux.h"
#include "os_io_seproxyhal.h"
#include "main.h"
#include "ssh_ux.h"
#include "callbacks.h"

#ifdef HAVE_BAGL

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

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
    io_seproxyhal_touch_ecdh_ok(NULL),
    {
      &C_icon_validate_14,
      "PGP Agent",
      "ECDH?"
    });
UX_STEP_VALID(
    ux_approval_pgp_ecdh_flow_2_step,
    pb,
    io_seproxyhal_touch_ecdh_cancel(NULL),
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


void ui_get_public_key(void) {
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

void ui_sign_ssh_blob(void) {
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

void ui_sign_generic_hash(void) {
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

void ui_sign_direct_hash(void) {
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


void ui_get_ecdh_secret(void) {
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


#endif // HAVE_BAGL