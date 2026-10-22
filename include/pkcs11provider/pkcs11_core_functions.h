#ifndef PKCS11_CORE_FUNCTIONS_H_
#define PKCS11_CORE_FUNCTIONS_H_

#include "pkcs11provider/pkcs11_types.h"

#include <openssl/macros.h>

#define ERR_core_raise(provctx, reason) \
	_internal_ERR_core_raise(provctx, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, reason)

void _internal_ERR_core_raise(const PKCS11_PROV_CTX *provctx, const char *file, int line, const char *func,
    uint32_t reason);

#endif /* PKCS11_CORE_FUNCTIONS_H_ */
