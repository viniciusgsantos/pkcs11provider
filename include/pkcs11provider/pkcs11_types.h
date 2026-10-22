#ifndef PKCS11_TYPES_H_
#define PKCS11_TYPES_H_

#include "pkcs11provider/pkcs11/pkcs11.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

struct params_functions_st {
	OSSL_FUNC_core_gettable_params_fn *core_gettable_params;
	OSSL_FUNC_core_get_params_fn *core_get_params;
};

struct error_functions_st {
	OSSL_FUNC_core_new_error_fn *core_new_error;
	OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
	OSSL_FUNC_core_vset_error_fn *core_vset_error;
};

struct pkcs11_prov_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
	struct params_functions_st *param_functions;
	struct error_functions_st *error_functions;
	void *module_handler;
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

typedef struct params_functions_st PARAMS_FUNCTIONS;
typedef struct error_functions_st ERROR_FUNCTIONS;
typedef struct pkcs11_prov_ctx_st PKCS11_PROV_CTX;
typedef struct pkcs11_prov_key_st PKCS11_PROV_KEY;

#endif /* PKCS11_TYPES_H_ */