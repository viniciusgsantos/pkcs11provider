/**
 * PKCS#11 works with a shared login state so, in order to avoid repeated login and guarantee the aplication
 * never logs out mid use, we rely on an anchor session managed by the provider that is never closed in regular user
 * operations.
 */
#ifndef SESSION_H_
#define SESSION_H_

#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/pkcs11_types.h"

int open_session(PKCS11_PROV_CTX *provctx, const CK_SLOT_ID slot_id, CK_SESSION_HANDLE *session_handle);
int close_session(PKCS11_PROV_CTX *provctx, CK_SESSION_HANDLE session_handle);
int user_login(PKCS11_PROV_CTX *provctx, const char *user_pin);
int user_logout(PKCS11_PROV_CTX *provctx);

static int open_anchor_session(PKCS11_PROV_CTX *provctx, const CK_SLOT_ID slot_id);

static int PKCS11_open_session(CK_FUNCTION_LIST_PTR method, const CK_SLOT_ID slot_id, CK_SESSION_HANDLE *session_handle);
static int PKCS11_close_session(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle);
static int PKCS11_login(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle, const char *user_pin);
static int PKCS11_logout(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle);

#endif /* SESSION_H_ */
