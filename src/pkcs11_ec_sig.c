#include "pkcs11provider/pkcs11_ec_sig.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_ec_keymgmt.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11/pkcs11.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <string.h>

static void *pkcs11_ec_sig_newctx(void *provctx, const char *propq)
{
    PKCS11_EC_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(PKCS11_EC_SIG_CTX));

	if (ctx != NULL)
		ctx->provctx = provctx;
	
	return ctx;
}

static void pkcs11_ec_sig_freectx(void *ctx)
{
    PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	if (sigctx)
		OPENSSL_free(sigctx);
}

static void *pkcs11_ec_sig_dupctx(void *ctx)
{
    PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	const OSSL_CORE_HANDLE *handle = sigctx->provctx->core_handle;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;

	if (!sigctx)
		return NULL;
	
	PKCS11_EC_SIG_CTX *newctx = OPENSSL_zalloc(sizeof(PKCS11_EC_SIG_CTX));
	if (!newctx) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		return NULL;
	}

	newctx->provctx = sigctx->provctx;
	/* TODO Open new session? */
	newctx->session_handle = sigctx->session_handle;
	newctx->n_len = sigctx->n_len;
	newctx->sig_len = sigctx->sig_len;

	return newctx;
}

static int pkcs11_ec_sig_sign_init(void *ctx, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_EC_KEYDATA *keydata = (PKCS11_EC_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	int curve_nid = curveName2nid(keydata->curve_name);
	if (curve_nid == NID_undef) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_nid);
	if (!ec_group) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	sigctx->n_len = (EC_GROUP_order_bits(ec_group) + 7) / 8;

	EC_GROUP_free(ec_group);

	CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};

	sigctx->session_handle = keydata->p11_handle->session_handle;
	CK_RV rv = method->C_SignInit(sigctx->session_handle, &mechanism, keydata->p11_handle->priv_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_ec_sig_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *tbs_tmp = (unsigned char *)(uintptr_t) tbs;

	unsigned char *sig_tmp = NULL;
	if (sigctx->sig_len > 0) {
		sig_tmp = OPENSSL_malloc(sigctx->sig_len);
		if (!sig_tmp) {
			ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
			goto err2;
		}
	}

	CK_ULONG ck_siglen = sig ? (CK_ULONG) siglen : 0;
	CK_RV rv = method->C_Sign(sigctx->session_handle, tbs_tmp, tbslen, sig_tmp, &ck_siglen);
	if (rv != CKR_OK && (rv != CKR_BUFFER_TOO_SMALL || sig_tmp)) {
		ERR_core_raise(provctx, rv);
		goto err1;
	}

	if ((rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) && !sig) {
		sigctx->sig_len = (size_t) ck_siglen;
		*siglen = (size_t) ck_siglen;
		return TRUE;
	}
	
	ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}
	
	BIGNUM *r = NULL, *s = NULL;
	
	r = BN_bin2bn(&sig_tmp[0], sigctx->n_len, NULL);
	s = BN_bin2bn(&sig_tmp[sigctx->n_len], sigctx->n_len, NULL);

	if (!r || !s) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		if (r) BN_free(r);
		if (s) BN_free(s);
		goto err0;
	}

	ECDSA_SIG_set0(ecdsa_sig, r, s);

	unsigned char *p = sig;

	int der_len = i2d_ECDSA_SIG(ecdsa_sig, &p);
	if (der_len <= 0) {
		ERR_core_raise(provctx, DER_ENCODING_ERROR);
		goto err0;
	};
	
	ECDSA_SIG_free(ecdsa_sig);
	OPENSSL_free(sig_tmp);

	return TRUE;

err0:
	ECDSA_SIG_free(ecdsa_sig);
err1:
	OPENSSL_free(sig_tmp);
err2:
	return FALSE;
}

static int pkcs11_ec_sig_verify_init(void *ctx, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_EC_KEYDATA *keydata = (PKCS11_EC_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;
	
	int curveNid = curveName2nid(keydata->curve_name);
	
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curveNid);
	if (!ec_group) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	sigctx->n_len = (EC_GROUP_order_bits(ec_group) + 7) / 8;

	EC_GROUP_free(ec_group);
	
	CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};

	CK_RV rv = method->C_VerifyInit(sigctx->session_handle, &mechanism, keydata->p11_handle->pub_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_ec_sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *tbs_tmp = (unsigned char *)(uintptr_t) tbs;

	ECDSA_SIG *ecdsa_sig = NULL;
	const unsigned char *p = sig;

	if ((ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, siglen)) == NULL) {
		ERR_core_raise(provctx, INVALID_ECDSA_SIGNATURE);
		goto err2;
	}

	const BIGNUM *r = NULL;
	const BIGNUM *s = NULL;

	ECDSA_SIG_get0(ecdsa_sig, &r, &s);
	if (!r || !s) {
		ERR_core_raise(provctx, INVALID_ECDSA_SIGNATURE);
		goto err2;
	}
	
	size_t raw_sig_len = sigctx->n_len * 2;
	unsigned char *raw_sig = OPENSSL_malloc(raw_sig_len);
	if (!raw_sig) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}

	BN_bn2binpad(r, raw_sig, sigctx->n_len);
	BN_bn2binpad(s, raw_sig + sigctx->n_len, sigctx->n_len);
	
	ECDSA_SIG_free(ecdsa_sig);
	
	int ret = TRUE;
	CK_RV rv = method->C_Verify(sigctx->session_handle, tbs_tmp, tbslen, raw_sig, raw_sig_len);
	if (rv != CKR_OK) {
		if (rv != CKR_SIGNATURE_INVALID && rv != CKR_SIGNATURE_LEN_RANGE)
			ERR_core_raise(provctx, rv);
		ret = FALSE;
	}

	OPENSSL_free(raw_sig);

	return ret;

err0:
	OPENSSL_free(raw_sig);
err1:
	ECDSA_SIG_free(ecdsa_sig);
err2:
	return FALSE;
}

static int pkcs11_ec_sig_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM *params)
{
    PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_EC_KEYDATA *keydata = (PKCS11_EC_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	int curve_nid = curveName2nid(keydata->curve_name);
	if (curve_nid == NID_undef) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_nid);
	if (!ec_group) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	sigctx->n_len = (EC_GROUP_order_bits(ec_group) + 7) / 8;

	EC_GROUP_free(ec_group);

	int mdnid = OBJ_sn2nid(mdname);
	if (mdnid == NID_undef) {
		mdnid = OBJ_ln2nid(mdname);
		if (mdnid == NID_undef) {
			ERR_core_raise(provctx, UNKNOWN_MD_ALGORITHM);
			return FALSE;	
		}
	}

	int mechanismId;
	if (mdnid == NID_sha1) {
		mechanismId = CKM_ECDSA_SHA1;
	} else {
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

static int pkcs11_ec_sig_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen)
{
    PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
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

static int pkcs11_ec_sig_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	unsigned char *sig_tmp = NULL;
	if (sigctx->sig_len > 0) {
		sig_tmp = OPENSSL_malloc(sigctx->sig_len);
		if (!sig_tmp) {
			ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
			goto err2;
		}
	}

	CK_RV rv;
	CK_ULONG ck_siglen = sig ? (CK_ULONG) *siglen : 0;
	rv = method->C_SignFinal(sigctx->session_handle, sig_tmp, &ck_siglen);
	if (rv != CKR_OK && (rv != CKR_BUFFER_TOO_SMALL || sig_tmp)) {
		ERR_core_raise(provctx, rv);
		goto err1;
	}

	if ((rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) && !sig) {
		sigctx->sig_len = (size_t) ck_siglen;
		*siglen = (size_t) ck_siglen;
		return TRUE;
	}

	BIGNUM *r = BN_bin2bn(&sig_tmp[0], sigctx->n_len, NULL);
	BIGNUM *s = BN_bin2bn(&sig_tmp[sigctx->n_len], sigctx->n_len, NULL);

	if (!r || !s) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		if (r) BN_free(r);
		if (s) BN_free(s);
		goto err1;
	}

	ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}
	ECDSA_SIG_set0(ecdsa_sig, r, s);

	unsigned char *p = sig;
	int der_len = i2d_ECDSA_SIG(ecdsa_sig, &p);
	if (der_len <= 0) {
		ERR_core_raise(provctx, DER_ENCODING_ERROR);
		goto err0;
	}

	*siglen = der_len;

	ECDSA_SIG_free(ecdsa_sig);
	OPENSSL_free(sig_tmp);

	return TRUE;

err0:
	ECDSA_SIG_free(ecdsa_sig);
err1:
	OPENSSL_free(sig_tmp);
err2:
	return FALSE;
}

static int pkcs11_ec_sig_digest_verify_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM *params)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_EC_KEYDATA *keydata = (PKCS11_EC_KEYDATA *) provkey;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	sigctx->session_handle = keydata->p11_handle->session_handle;

	int curveNid = curveName2nid(keydata->curve_name);
	
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curveNid);
	if (!ec_group) {
		ERR_core_raise(provctx, UNKNOWN_CURVE_NAME);
		return FALSE;
	}
	
	sigctx->n_len = (EC_GROUP_order_bits(ec_group) + 7) / 8;

	EC_GROUP_free(ec_group);

	int mdnid = OBJ_sn2nid(mdname);
	if (mdnid == NID_undef) {
		mdnid = OBJ_ln2nid(mdname);
		if (mdnid == NID_undef) {
			ERR_core_raise(provctx, UNKNOWN_MD_ALGORITHM);
			return FALSE;	
		}
	}

	int mechanismId;
	if (mdnid == NID_sha1) {
		mechanismId = CKM_ECDSA_SHA1;
	} else {
		ERR_core_raise(provctx, NO_MECHANISM_AVAILABLE);
		return FALSE;	
	}

	CK_MECHANISM mechanism = {mechanismId, NULL, 0};

	CK_RV rv = method->C_VerifyInit(sigctx->session_handle, &mechanism, keydata->p11_handle->pub_key_handle);
	if (rv != CKR_OK) {
		ERR_core_raise(provctx, rv);
		return FALSE;
	}

	return TRUE;
}

static int pkcs11_ec_sig_digest_verify_update(void *ctx, const unsigned char *data, size_t datalen)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
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

static int pkcs11_ec_sig_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
	PKCS11_EC_SIG_CTX *sigctx = (PKCS11_EC_SIG_CTX *) ctx;
	PKCS11_PROV_CTX *provctx = sigctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;

	ECDSA_SIG *ecdsa_sig;
	const BIGNUM *r = NULL;
	const BIGNUM *s = NULL;
	
	const unsigned char *p = sig;

	if ((ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, siglen)) == NULL) {
		ERR_core_raise(provctx, INVALID_ECDSA_SIGNATURE);
		goto err0;
	}

	ECDSA_SIG_get0(ecdsa_sig, &r, &s);
	if (!r || !s) {
		ERR_core_raise(provctx, INVALID_ECDSA_SIGNATURE);
		goto err0;
	}
	
	size_t raw_sig_len = sigctx->n_len * 2;
	unsigned char *raw_sig = OPENSSL_zalloc(raw_sig_len);
	if (!raw_sig) {
		ERR_core_raise(provctx, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}

	BN_bn2binpad(r, raw_sig, sigctx->n_len);
	BN_bn2binpad(s, raw_sig + sigctx->n_len, sigctx->n_len);
	
	ECDSA_SIG_free(ecdsa_sig);

	int ret;

	ret = method->C_VerifyFinal(sigctx->session_handle, raw_sig, raw_sig_len);
	if (ret != CKR_OK) {
		if (ret != CKR_SIGNATURE_INVALID && ret != CKR_SIGNATURE_LEN_RANGE)
			ERR_core_raise(provctx, ret);
		return FALSE;
	}

	OPENSSL_free(raw_sig);
	return TRUE;

err0:
	method->C_VerifyFinal(sigctx->session_handle, NULL, 0);
	return FALSE;
err1:
	OPENSSL_free(raw_sig);
	return FALSE;
}

const OSSL_DISPATCH pkcs11_ec_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) pkcs11_ec_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) pkcs11_ec_sig_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) pkcs11_ec_sig_dupctx },
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) pkcs11_ec_sig_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) pkcs11_ec_sig_sign },
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) pkcs11_ec_sig_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) pkcs11_ec_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) pkcs11_ec_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) pkcs11_ec_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void)) pkcs11_ec_sig_digest_sign_final },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) pkcs11_ec_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) pkcs11_ec_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) pkcs11_ec_sig_digest_verify_final },
    {0, NULL}
};