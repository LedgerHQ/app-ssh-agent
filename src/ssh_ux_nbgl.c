#ifdef HAVE_NBGL

#include "callbacks.h"
#include "main.h"
#include "nbgl_use_case.h"
#include "os_helpers.h"
#include "ux.h"

void ui_idle(void);

void app_quit() {
    os_sched_exit(-1);
}

static const char *const infoTypes[]    = {"Version", "Developer", "Copyright"};
static const char *const infoContents[] = {APPVERSION, "Ledger", "(c) 2023 Ledger"};

static bool navigation_cb(uint8_t page, nbgl_pageContent_t *content) {
    UNUSED(page);
    content->type                   = INFOS_LIST;
    content->infosList.nbInfos      = 3;
    content->infosList.infoTypes    = infoTypes;
    content->infosList.infoContents = infoContents;
    return true;
}

void app_settings() {
    nbgl_useCaseSettings(APPNAME, 0, 1, false, ui_idle, navigation_cb, NULL);
}

void ui_idle(void) {
    nbgl_useCaseHome(APPNAME, &C_icon_app_ssh_64px, "Application is ready.", false, app_settings,
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
    nbgl_useCaseChoice(&C_warning64px, "Provide public key?", NULL, "Allow", "Reject",
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
    nbgl_useCaseChoice(&C_warning64px, "Connect SSH user", (char *) operationContext.userName,
                       "Allow", "Reject", ui_sign_ssh_blob_choice);
}

static void ui_get_ecdh_secret_choice(bool choice) {
    if (choice) {
        io_seproxyhal_touch_ecdh_ok(NULL);
    } else {
        io_seproxyhal_touch_ecdh_cancel(NULL);
    }
}

void ui_get_ecdh_secret(void) {
    nbgl_useCaseChoice(&C_warning64px, "PGP Agent", "Allow ECDH?", "Allow", "Reject",
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
    nbgl_useCaseChoice(&C_warning64px, "PGP Agent", "Sign?", "Allow", "Reject",
                       ui_sign_generic_hash_choice);
}

void ui_sign_direct_hash(void) {
    ui_sign_generic_hash();
}

#endif