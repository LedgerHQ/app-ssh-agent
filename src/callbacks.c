
#include "callbacks.h"
#include "main.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "os.h"
#include "ssh_ux.h"

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
   (void) e;
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e) {
    (void) e;

    uint8_t privateKeyData[32];
    uint8_t hash[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    if (!operationContext.direct) {
        if (!operationContext.fullMessageHash) {
            cx_hash(&operationContext.hash.header, CX_LAST, hash, 0, hash, sizeof(hash));
        }
    } else {
        memmove(hash, operationContext.hashData, 32);
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
    memset(privateKeyData, 0, sizeof(privateKeyData));
    if (operationContext.curve == CX_CURVE_Ed25519) {
        if (!operationContext.fullMessageHash) {
#if CX_APILEVEL >= 8
            tx = cx_eddsa_sign(&privateKey, CX_LAST, CX_SHA512, hash,
                               sizeof(hash), NULL, 0, G_io_apdu_buffer, sizeof(G_io_apdu_buffer), NULL);
#else
            tx = cx_eddsa_sign(&privateKey, NULL, CX_LAST, CX_SHA512, hash,
                               sizeof(hash), G_io_apdu_buffer);
#endif
        } else {
#if CX_APILEVEL >= 8
            tx = cx_eddsa_sign(
                &privateKey, CX_LAST, CX_SHA512, operationContext.message,
                operationContext.messageLength, NULL, 0, G_io_apdu_buffer, sizeof(G_io_apdu_buffer), NULL);
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
                           hash, sizeof(hash), G_io_apdu_buffer, sizeof(G_io_apdu_buffer), &info);
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
        memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
        tx += 65;
    }
    memset(&privateKey, 0, sizeof(privateKey));
    memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e) {
    (void) e;

    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e) {
    (void) e;

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
    tx = cx_ecdh(&privateKey, CX_ECDH_POINT, operationContext.publicKey.W, operationContext.publicKey.W_len,
                 G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    memset(&privateKey, 0, sizeof(privateKey));
    memset(&privateKeyData, 0, sizeof(privateKeyData));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e) {
    (void) e;

    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    (void) e;

    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = 65;
    memmove(G_io_apdu_buffer + tx, operationContext.publicKey.W, 65);
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
    (void) e;

    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}
