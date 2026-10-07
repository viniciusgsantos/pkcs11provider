#ifndef PKCS11_RSA_SIG_H_
#define PKCS11_RSA_SIG_H_

#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/pkcs11_types.h"

#include <openssl/core_dispatch.h>
#include <openssl/types.h>

struct pkcs11_rsa_sig_ctx_st {
	struct pkcs11_prov_ctx_st *provctx;
	CK_SESSION_HANDLE session_handle;
	int mdnid;
	EVP_MD_CTX *mdctx;
	unsigned char *digest_info;
	size_t digest_info_len;
};

typedef struct pkcs11_rsa_sig_ctx_st PKCS11_RSA_SIG_CTX;

static OSSL_FUNC_signature_newctx_fn pkcs11_rsa_sig_newctx;
static OSSL_FUNC_signature_freectx_fn pkcs11_rsa_sig_freectx;
static OSSL_FUNC_signature_sign_init_fn pkcs11_rsa_sig_sign_init;
static OSSL_FUNC_signature_sign_fn pkcs11_rsa_sig_sign;
static OSSL_FUNC_signature_verify_init_fn pkcs11_rsa_sig_verify_init;
static OSSL_FUNC_signature_verify_fn pkcs11_rsa_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn pkcs11_rsa_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn pkcs11_rsa_sig_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn pkcs11_rsa_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn pkcs11_rsa_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn pkcs11_rsa_sig_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn pkcs11_rsa_sig_digest_verify_final;

const extern OSSL_DISPATCH pkcs11_rsa_fns[14];

#endif /* PKCS11_RSA_SIG_H_ */