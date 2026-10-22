#include "pkcs11provider/pkcs11_core_functions.h"

void _internal_ERR_core_raise(const PKCS11_PROV_CTX *provctx, const char *file, int line, const char *func,
    uint32_t reason)
{
    if (provctx->error_functions->core_new_error)
        provctx->error_functions->core_new_error(provctx->core_handle);
	
    if (provctx->error_functions->core_set_error_debug)
        provctx->error_functions->core_set_error_debug(provctx->core_handle, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC);
	
    if (provctx->error_functions->core_vset_error)
        provctx->error_functions->core_vset_error(provctx->core_handle, reason, NULL, NULL);
}