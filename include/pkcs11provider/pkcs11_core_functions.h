#ifndef PKCS11_CORE_FUNCTIONS_H_
#define PKCS11_CORE_FUNCTIONS_H_

#include <openssl/core_dispatch.h>

#define ERR_core_raise(handle, reason) \
	_internal_ERR_core_raise(handle, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, reason)

void init_get_params_functions(OSSL_FUNC_core_gettable_params_fn *_core_gettable_params,
                               OSSL_FUNC_core_get_params_fn *_core_get_params);

void init_error_functions(OSSL_FUNC_core_new_error_fn *_core_new_error,
                          OSSL_FUNC_core_set_error_debug_fn *_core_set_error_debug,
                          OSSL_FUNC_core_vset_error_fn *_core_vset_error);

void _internal_ERR_core_raise(const OSSL_CORE_HANDLE *handle, const char *file, int line, const char *func, 
                              uint32_t reason);

#endif /* PKCS11_CORE_FUNCTIONS_H_ */
