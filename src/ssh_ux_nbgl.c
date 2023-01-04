#ifdef HAVE_NBGL

#include "os_helpers.h"
#include "ux.h"
#include "callbacks.h"
#include "nbgl_use_case.h"
#include "main.h"

void app_quit() {
  io_seproxyhal_touch_exit(NULL);
}

void ui_idle(void) {
  nbgl_useCaseHome(APPNAME,
                    NULL,
                    APPNAME,
                    false,
                    NULL,
                    app_quit);
}


static void ui_get_public_key_choice(bool choice) {
  if (choice) {
    io_seproxyhal_touch_address_ok(NULL);
  } else {
    io_seproxyhal_touch_address_cancel(NULL);
  }
}

void ui_get_public_key(void) {
  nbgl_useCaseChoice(&C_warning64px,
                     "Provide public key?",
                      NULL,
                      "Allow",
                      "Reject",
                      ui_get_public_key_choice);
}


static void ui_sign_ssh_blob_choice(bool choice) {
  if (choice) {
    io_seproxyhal_touch_sign_ok(NULL);
  } else {
    io_seproxyhal_touch_address_cancel(NULL);
  }
}

void ui_sign_ssh_blob(void) {
  nbgl_useCaseChoice(&C_warning64px,
                     "Connect SSH user",
                      (char*) operationContext.userName,
                      "Allow",
                      "Reject",
                      ui_sign_ssh_blob_choice);
}

static void ui_get_ecdh_secret_choice(bool choice) {
  if (choice) {
    io_seproxyhal_touch_ecdh_ok(NULL);
  } else {
    io_seproxyhal_touch_ecdh_cancel(NULL);
  }
}

void ui_get_ecdh_secret(void) {
  nbgl_useCaseChoice(&C_warning64px,
                     "PGP Agent",
                      "Allow ECDH?",
                      "Allow",
                      "Reject",
                      ui_get_ecdh_secret_choice);
}

static void ui_sign_generic_hash_choice(bool choice) {
  if (choice) {
    io_seproxyhal_touch_sign_ok(NULL);
  } else {
    io_seproxyhal_touch_sign_cancel(NULL);
  }
}
void ui_sign_generic_hash(void) {
  nbgl_useCaseChoice(&C_warning64px,
                     "PGP Agent",
                      "Sign?",
                      "Allow",
                      "Reject",
                      ui_sign_generic_hash_choice);
}

void ui_sign_direct_hash(void) {
  ui_sign_generic_hash();
}

#endif