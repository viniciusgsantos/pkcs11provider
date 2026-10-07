#include "pkcs11provider/pkcs11_core_functions.h"

static OSSL_FUNC_core_gettable_params_fn *core_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;

void init_get_params_functions(OSSL_FUNC_core_gettable_params_fn *_core_gettable_params,
                               OSSL_FUNC_core_get_params_fn *_core_get_params)
{
    core_gettable_params = _core_gettable_params;
    core_get_params = _core_get_params;
}

void init_error_functions(OSSL_FUNC_core_new_error_fn *_core_new_error,
                          OSSL_FUNC_core_set_error_debug_fn *_core_set_error_debug,
                          OSSL_FUNC_core_vset_error_fn *_core_vset_error)
{
    core_new_error = _core_new_error;
    core_set_error_debug = _core_set_error_debug;
    core_vset_error = _core_vset_error;
}

void _internal_ERR_core_raise(const OSSL_CORE_HANDLE *handle, const char *file, int line, const char *func, 
                              uint32_t reason)
{
    if (core_new_error)
        core_new_error(handle);
	
    if (core_set_error_debug)
        core_set_error_debug(handle, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC);
	
    if (core_vset_error)
        core_vset_error(handle, reason, NULL, NULL);
}