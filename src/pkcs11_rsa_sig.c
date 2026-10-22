#include "pkcs11provider/pkcs11_rsa_sig.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_rsa_keymgmt.h"
#include "pkcs11provider/pkcs11/pkcs11.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <string.h>

static void *pkcs11_rsa_sig_newctx(void *provctx, const char *propq)
{
	PKCS11_PROV_CTX *pctx = (PKCS11_PROV_CTX *) provctx;
	const OSSL_CORE_HANDLE *handle = pctx->core_handle;
    PKCS11_RSA_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(PKCS11_RSA_SIG_CTX));

	if (!ctx) {
		ERR_core_raise(pctx, MEMORY_ALLOCATION_ERROR);
		return NULL;
	}

	ctx->provctx = pctx;
	
	return ctx;
}

static void pkcs11_rsa_sig_freectx(void *ctx)
{
    PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	if (sigctx)
		OPENSSL_free(sigctx);
}

static void *pkcs11_rsa_sig_dupctx(void *ctx)
{
    PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;

	if (!sigctx)
		return NULL;

	PKCS11_RSA_SIG_CTX *newctx = OPENSSL_zalloc(sizeof(PKCS11_RSA_SIG_CTX));
	if (!newctx) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		return NULL;
	}
	newctx->provctx = sigctx->provctx;
	/* TODO Open new session? */
	newctx->session_handle = sigctx->session_handle;

	return newctx;
}

static int pkcs11_rsa_sig_sign_init(void *ctx, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_RSA_KEYDATA *keydata = (PKCS11_RSA_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};

	CK_RV rv = method->C_SignInit(sigctx->session_handle, &mechanism, keydata->p11_handle->priv_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *tbs_tmp = (unsigned char *)(uintptr_t) tbs;

	int ret = TRUE;

	CK_ULONG ck_siglen = sig ? (CK_ULONG) *siglen : 0;
	CK_RV rv = method->C_Sign(sigctx->session_handle, tbs_tmp, tbslen, sig, &ck_siglen);
	if (ret != CKR_OK && (rv != CKR_BUFFER_TOO_SMALL || sig)) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	if ((ret == CKR_OK || ret == CKR_BUFFER_TOO_SMALL) && !sig)
		*siglen = (size_t) ck_siglen;

	return TRUE;
}

static int pkcs11_rsa_sig_verify_init(void *ctx, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_RSA_KEYDATA *keydata = (PKCS11_RSA_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};

	CK_RV rv = method->C_VerifyInit(sigctx->session_handle, &mechanism, keydata->p11_handle->pub_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *tbs_tmp = (unsigned char *)(uintptr_t) tbs;
	unsigned char *sig_tmp = (unsigned char *)(uintptr_t) sig;
	
	CK_RV rv = method->C_Verify(sigctx->session_handle, tbs_tmp, tbslen, sig_tmp, siglen);
	if (rv != CKR_OK) {
		if (rv != CKR_SIGNATURE_INVALID)
			ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_RSA_KEYDATA *keydata = (PKCS11_RSA_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	int mdnid = OBJ_sn2nid(mdname);
	if (mdnid == NID_undef) {
		mdnid = OBJ_ln2nid(mdname);
		if (mdnid == NID_undef) {
			ERR_core_raise(provctx, UNKNOWN_MD_ALGORITHM);
			return FALSE;	
		}
	}

	int mechanismId;
	switch (mdnid) {
	case NID_md2:
		mechanismId = CKM_MD2_RSA_PKCS;
		break;
	case NID_md5:
		mechanismId = CKM_MD5_RSA_PKCS;
		break;
	case NID_sha1:
		mechanismId = CKM_SHA1_RSA_PKCS;
		break;
	case NID_ripemd160:
		mechanismId = CKM_RIPEMD160_RSA_PKCS;
		break;
	case NID_sha256:
		mechanismId = CKM_SHA256_RSA_PKCS;
		break;
	case NID_sha384:
		mechanismId = CKM_SHA384_RSA_PKCS;
		break;
	case NID_sha512:
		mechanismId = CKM_SHA512_RSA_PKCS;
		break;
	default:
		ERR_core_raise(provctx, NO_MECHANISM_AVAILABLE);
		return FALSE;	
	}

	CK_MECHANISM mechanism = {mechanismId, NULL, 0};

	CK_RV rv = method->C_SignInit(sigctx->session_handle, &mechanism, keydata->p11_handle->priv_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *data_tmp = (unsigned char *)(uintptr_t) data;
	CK_RV rv = method->C_SignUpdate(sigctx->session_handle, data_tmp, datalen);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	int ret;

	CK_ULONG ck_siglen = sig ? (CK_ULONG) *siglen : 0;
	ret = method->C_SignFinal(sigctx->session_handle, sig, &ck_siglen);
	if (ret != CKR_OK && (ret != CKR_BUFFER_TOO_SMALL || sig)) {
		ERR_core_raise(provctx, ret);
		return FALSE;
	}

	if ((ret == CKR_OK || ret == CKR_BUFFER_TOO_SMALL) && !sig)
		*siglen = (size_t) ck_siglen;

	return TRUE;
}

static int pkcs11_rsa_sig_digest_verify_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_RSA_KEYDATA *keydata = (PKCS11_RSA_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	int mdnid = OBJ_sn2nid(mdname);
	if (mdnid == NID_undef) {
		mdnid = OBJ_ln2nid(mdname);
		if (mdnid == NID_undef) {
			ERR_core_raise(provctx, UNKNOWN_MD_ALGORITHM);
			return FALSE;	
		}
	}

	int mechanismId;
	switch (mdnid) {
	case NID_md2:
		mechanismId = CKM_MD2_RSA_PKCS;
		break;
	case NID_md5:
		mechanismId = CKM_MD5_RSA_PKCS;
		break;
	case NID_sha1:
		mechanismId = CKM_SHA1_RSA_PKCS;
		break;
	case NID_ripemd160:
		mechanismId = CKM_RIPEMD160_RSA_PKCS;
		break;
	case NID_sha256:
		mechanismId = CKM_SHA256_RSA_PKCS;
		break;
	case NID_sha384:
		mechanismId = CKM_SHA384_RSA_PKCS;
		break;
	case NID_sha512:
		mechanismId = CKM_SHA512_RSA_PKCS;
		break;
	default:
		ERR_core_raise(provctx, NO_MECHANISM_AVAILABLE);
		return FALSE;
	}

	CK_MECHANISM verify_mechanism = {mechanismId, NULL, 0};

	CK_RV rv = method->C_VerifyInit(sigctx->session_handle, &verify_mechanism, keydata->p11_handle->pub_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_digest_verify_update(void *ctx, const unsigned char *data, size_t datalen)
{
    PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *data_tmp = (unsigned char *)(uintptr_t) data;
	CK_RV rv = method->C_VerifyUpdate(sigctx->session_handle, data_tmp, datalen);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_rsa_sig_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
	PKCS11_RSA_SIG_CTX *sigctx = (PKCS11_RSA_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *sig_tmp = (unsigned char *)(uintptr_t) sig;

	int ret = method->C_VerifyFinal(sigctx->session_handle, sig_tmp, siglen);
	if (ret != CKR_OK) {
		if (ret != CKR_SIGNATURE_INVALID && ret != CKR_SIGNATURE_LEN_RANGE)
			ERR_core_raise(provctx, ret);
		return FALSE;
	}

	return TRUE;
}

const OSSL_DISPATCH pkcs11_rsa_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) pkcs11_rsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) pkcs11_rsa_sig_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) pkcs11_rsa_sig_dupctx },
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) pkcs11_rsa_sig_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) pkcs11_rsa_sig_sign },
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) pkcs11_rsa_sig_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) pkcs11_rsa_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) pkcs11_rsa_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) pkcs11_rsa_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) pkcs11_rsa_sig_digest_sign_final },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) pkcs11_rsa_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) pkcs11_rsa_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) pkcs11_rsa_sig_digest_verify_final },
    {0, NULL}
};
