#ifndef SSH_UX_H_
#define SSH_UX_H_

void ui_idle(void);
void ui_get_public_key(void);
void ui_sign_ssh_blob(void);
void ui_get_ecdh_secret(void);
void ui_sign_generic_hash(void);
void ui_sign_direct_hash(void);

#endif // SSH_UX_H_
