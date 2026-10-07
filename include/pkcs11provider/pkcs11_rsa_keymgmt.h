#ifndef PKCS11_RSA_KEYMGMT_H_
#define PKCS11_RSA_KEYMGMT_H_

#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/pkcs11_types.h"

#include <openssl/types.h>
#include <openssl/core_dispatch.h>

struct pkcs11_rsa_keydata_st {
	struct pkcs11_prov_ctx_st *provctx;
	struct pkcs11_prov_key_st *p11_handle;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;
	char *label;
	int is_priv;
	int extractable;
};

struct pkcs11_rsa_keymgmt_gen_ctx_st {
	struct pkcs11_prov_ctx_st *provctx;
	unsigned long slot_id;
	char *pin;
	int key_len;
	int public_exponent;
	char *label;
	int extractable;
	int x9_31;
};

typedef struct pkcs11_rsa_keydata_st PKCS11_RSA_KEYDATA;
typedef struct pkcs11_rsa_keymgmt_gen_ctx_st PKCS11_RSA_KEYMGMT_GEN_CTX;

static OSSL_FUNC_keymgmt_new_fn pkcs11_rsa_keymgmt_new;
static OSSL_FUNC_keymgmt_free_fn pkcs11_rsa_keymgmt_free;
static OSSL_FUNC_keymgmt_gen_init_fn pkcs11_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn pkcs11_rsa_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn pkcs11_rsa_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn pkcs11_rsa_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn pkcs11_rsa_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn pkcs11_rsa_keymgmt_load;
static OSSL_FUNC_keymgmt_has_fn pkcs11_rsa_keymgmt_has;
static OSSL_FUNC_keymgmt_query_operation_name_fn pkcs11_rsa_keymgmt_query_operation_name;
static OSSL_FUNC_keymgmt_import_fn pkcs11_rsa_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn pkcs11_rsa_keymgmt_import_types;
static OSSL_FUNC_keymgmt_export_fn pkcs11_rsa_keymgmt_export;
static OSSL_FUNC_keymgmt_export_types_fn pkcs11_rsa_keymgmt_export_types;

const extern OSSL_DISPATCH pkcs11_rsa_keymgmt_fns[14];

#endif /* PKCS11_RSA_KEYMGMT_H_ */