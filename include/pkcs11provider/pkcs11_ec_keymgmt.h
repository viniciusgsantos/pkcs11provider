#ifndef PKCS11_EC_KEYMGMT_H_
#define PKCS11_EC_KEYMGMT_H_

#include "pkcs11provider/pkcs11_types.h"

#include <openssl/core_dispatch.h>
#include <openssl/types.h>

struct pkcs11_ec_keydata_st {
	struct pkcs11_prov_ctx_st *provctx;
	struct pkcs11_prov_key_st *p11_handle;
	const char *curve_name;
	BIGNUM *pub_x;
	BIGNUM *pub_y;
	BIGNUM *priv;
	char *label;
	int is_priv;
	int extractable;
};

struct pkcs11_ec_keymgmt_gen_ctx_st {
	struct pkcs11_prov_ctx_st *provctx;
	unsigned long slot_id;
	char *pin;
	const char *curve_name;
	char *label;
	int extractable;
};

typedef struct pkcs11_ec_keydata_st PKCS11_EC_KEYDATA;
typedef struct pkcs11_ec_keymgmt_gen_ctx_st PKCS11_EC_KEYMGMT_GEN_CTX;

static OSSL_FUNC_keymgmt_new_fn pkcs11_ec_keymgmt_new;
static OSSL_FUNC_keymgmt_free_fn pkcs11_ec_keymgmt_free;
static OSSL_FUNC_keymgmt_gen_init_fn pkcs11_ec_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn pkcs11_ec_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn pkcs11_ec_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn pkcs11_ec_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn pkcs11_ec_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn pkcs11_ec_keymgmt_load;
static OSSL_FUNC_keymgmt_has_fn pkcs11_ec_keymgmt_has;
static OSSL_FUNC_keymgmt_import_fn pkcs11_ec_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn pkcs11_ec_keymgmt_import_types;
static OSSL_FUNC_keymgmt_export_fn pkcs11_ec_keymgmt_export;
static OSSL_FUNC_keymgmt_export_types_fn pkcs11_ec_keymgmt_export_types;

const extern OSSL_DISPATCH pkcs11_ec_keymgmt_fns[14];

#endif /* PKCS11_EC_KEYMGMT_H_ */