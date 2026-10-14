#ifndef PKCS11_TYPES_H_
#define PKCS11_TYPES_H_

#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/pkcs11_types.h"

#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

struct pkcs11_prov_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
	void *module_handler;
	int pkcs11_initialized;
	char *module_path;
	char *pkcs11_init_args;
	CK_SESSION_HANDLE anchor_session;
	int has_anchor_session;
	int is_logged_in;
	CK_FUNCTION_LIST_PTR method;
	int verifyInHardware;
};

struct pkcs11_prov_key_st {
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE priv_key_handle;
	CK_OBJECT_HANDLE pub_key_handle;
	int has_priv_key_handle;
	int has_pub_key_handle;
};

typedef struct pkcs11_prov_ctx_st PKCS11_PROV_CTX;
typedef struct pkcs11_prov_key_st PKCS11_PROV_KEY;

#endif /* PKCS11_TYPES_H_ */