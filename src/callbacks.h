#ifndef CALLBACKS_H_
#define CALLBACKS_H_

#include "ux.h"

#ifdef TARGET_FATSTACKS
typedef uint32_t bagl_element_t;
#endif

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_ecdh_cancel(const bagl_element_t *e);

#endif // CALLBACKS_H_
