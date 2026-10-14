#include "pkcs11provider/pkcs11_rsa_keymgmt.h"
#include "pkcs11provider/pkcs11_attr.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_store.h"
#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/session.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <string.h>

static void *pkcs11_rsa_keymgmt_new(void *provctx)
{
	PKCS11_RSA_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_RSA_KEYDATA));
	keydata->p11_handle = OPENSSL_zalloc(sizeof(PKCS11_PROV_KEY));
	keydata->provctx = (PKCS11_PROV_CTX *) provctx;
	return keydata;
}

static void pkcs11_rsa_keymgmt_free(void *keydata)
{
	PKCS11_RSA_KEYDATA *key = (PKCS11_RSA_KEYDATA *) keydata;
	if (key) {
		OPENSSL_free(key->p11_handle);
		BN_free(key->n);
		BN_free(key->e);
		BN_clear_free(key->d);
		BN_clear_free(key->p);
		BN_clear_free(key->q);
		BN_clear_free(key->dmp1);
		BN_clear_free(key->dmq1);
		BN_clear_free(key->iqmp);
		OPENSSL_free(key->label);
		OPENSSL_free(key);
	}
}

static void *pkcs11_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM *params)
{
	PKCS11_RSA_KEYMGMT_GEN_CTX *genctx = OPENSSL_zalloc(sizeof(PKCS11_RSA_KEYMGMT_GEN_CTX));
	genctx->provctx = (PKCS11_PROV_CTX *) provctx;
	CK_FUNCTION_LIST_PTR method = genctx->provctx->method;
	const OSSL_CORE_HANDLE *handle = genctx->provctx->core_handle;

	if (params) {
		int i;
		for (i = 0; params[i].key != NULL; i++) {
			if (strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_BITS) == 0) {
				genctx->key_len = *(unsigned int *) params[i].data;
			} else if (strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_E) == 0) {
				genctx->public_exponent = *(unsigned int *) params[i].data;
			} else if (strcmp(params[i].key, "slot-id") == 0) {
				unsigned char *slot_id_arg = OPENSSL_malloc(params[i].data_size + 1);
				if (!slot_id_arg) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(slot_id_arg, params[i].data, params[i].data_size + 1);
				if (!PKCS11_HELPER_slot_label_to_id(method, slot_id_arg, &genctx->slot_id)) {
					ERR_core_raise(handle, SLOT_ID_PARSING_ERROR);
					return FALSE;
				}
			} else if (strcmp(params[i].key, "pin-value") == 0) {
				genctx->pin = OPENSSL_malloc(params[i].data_size + 1);
				if (!genctx->pin) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(genctx->pin, params[i].data, params[i].data_size + 1);
			} else if (strcmp(params[i].key, "label") == 0) {
				genctx->label = OPENSSL_malloc(params[i].data_size + 1);
				if (!genctx->label) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(genctx->label, params[i].data, params[i].data_size + 1);
			} else if (strcmp(params[i].key, "extractable") == 0) {
				genctx->extractable = *((int *) params[i].data);
			} else if (strcmp(params[i].key, "X9.31") == 0) {
				genctx->x9_31 = *((int *) params[i].data);
			}
		}
	}

	return genctx;
}

static int pkcs11_rsa_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM *params)
{
	PKCS11_RSA_KEYMGMT_GEN_CTX *gctx = (PKCS11_RSA_KEYMGMT_GEN_CTX *) genctx;
	CK_FUNCTION_LIST_PTR method = gctx->provctx->method;
	const OSSL_CORE_HANDLE *handle = gctx->provctx->core_handle;

	if (params) {
		int i;
		for (i = 0; params[i].key != NULL; i++) {
			if (strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_BITS) == 0) {
				gctx->key_len = *(unsigned int *) params[i].data;
			} else if (strcmp(params[i].key, OSSL_PKEY_PARAM_RSA_E) == 0) {
				gctx->public_exponent = *(unsigned int *) params[i].data;
			} else if (strcmp(params[i].key, "slot-id") == 0) {
				unsigned char *slot_id_arg = OPENSSL_malloc(params[i].data_size + 1);
				if (!slot_id_arg) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(slot_id_arg, params[i].data, params[i].data_size + 1);
				if (PKCS11_HELPER_slot_label_to_id(method, slot_id_arg, &gctx->slot_id) != 0) {
					ERR_core_raise(handle, SLOT_ID_PARSING_ERROR);
					OPENSSL_free(slot_id_arg);
					return FALSE;
				}
				OPENSSL_free(slot_id_arg);
			} else if (strcmp(params[i].key, "pin-value") == 0) {
				gctx->pin = OPENSSL_malloc(params[i].data_size + 1);
				if (!gctx->pin) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(gctx->pin, params[i].data, params[i].data_size + 1);
			} else if (strcmp(params[i].key, "label") == 0) {
				gctx->label = OPENSSL_malloc(params[i].data_size + 1);
				if (!gctx->label) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(gctx->label, params[i].data, params[i].data_size + 1);
			} else if (strcmp(params[i].key, "extractable") == 0) {
				gctx->extractable = *((int *) params[i].data);
			} else if (strcmp(params[i].key, "X9.31") == 0) {
				gctx->x9_31 = *((int *) params[i].data);
			}
		}
	}

	return TRUE;
}

static const OSSL_PARAM *pkcs11_rsa_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
	static const OSSL_PARAM gen_settable_params[] = {
		OSSL_PARAM_int32(OSSL_PKEY_PARAM_RSA_N, NULL),
		OSSL_PARAM_int32(OSSL_PKEY_PARAM_RSA_E, NULL),
		OSSL_PARAM_utf8_string("slot-id", NULL, 0),
		OSSL_PARAM_utf8_string("pin-value", NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int32("extractable", NULL),
		OSSL_PARAM_int32("X9.31", NULL),
		OSSL_PARAM_END
	};

	return gen_settable_params;
}


static void *pkcs11_rsa_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
	PKCS11_RSA_KEYMGMT_GEN_CTX *gctx = (PKCS11_RSA_KEYMGMT_GEN_CTX *) genctx;
	PKCS11_PROV_CTX *provctx = gctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;
	const OSSL_CORE_HANDLE *handle = gctx->provctx->core_handle;

	CK_MECHANISM mechanism;
	mechanism.mechanism = gctx->x9_31 ? CKM_RSA_X9_31_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	CK_BYTE public_exponent_bytes[4];
	CK_ULONG public_exponent_bytes_len = 0;
	uint32_t public_exponent = (uint32_t) gctx->public_exponent;

	if (public_exponent > 0xFFFFFF)
		public_exponent_bytes[public_exponent_bytes_len++] = (public_exponent >> 24) & 0xFF;
	
	if (public_exponent > 0xFFFF)
		public_exponent_bytes[public_exponent_bytes_len++] = (public_exponent >> 16) & 0xFF;
	
	if (public_exponent > 0xFF)
		public_exponent_bytes[public_exponent_bytes_len++] = (public_exponent >> 8) & 0xFF;
	
	public_exponent_bytes[public_exponent_bytes_len++] = public_exponent & 0xFF;

	size_t random_id_len = 20;
	unsigned char random_id[random_id_len];
	RAND_bytes(random_id, sizeof(random_id));

	CK_ATTRIBUTE pub_key_template[32];
	CK_ATTRIBUTE priv_key_template[32];

	int i = 0, j = 0;
	pub_key_template[i++] = makeObjectClassAttribute(CKA_CLASS, CKO_PUBLIC_KEY);
	pub_key_template[i++] = makeBooleanAttribute(CKA_TOKEN, TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_PRIVATE, FALSE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_MODIFIABLE, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_ENCRYPT, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_VERIFY, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_WRAP, CK_TRUE);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_PUBLIC_EXPONENT, public_exponent_bytes,
		public_exponent_bytes_len);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_MODULUS_BITS, gctx->key_len);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_ID, random_id, random_id_len);
	pub_key_template[i++] = makeUTF8Attribute(CKA_LABEL, gctx->label);

	if (!check_attributes_data(pub_key_template, i)) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}

	priv_key_template[j++] = makeObjectClassAttribute(CKA_CLASS, CKO_PRIVATE_KEY);
	priv_key_template[j++] = makeBooleanAttribute(CKA_TOKEN, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_PRIVATE, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_MODIFIABLE, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_DECRYPT, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_SIGN, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_UNWRAP, CK_TRUE);
	priv_key_template[j++] = makeBooleanAttribute(CKA_SENSITIVE, !gctx->extractable);
	priv_key_template[j++] = makeBooleanAttribute(CKA_EXTRACTABLE, gctx->extractable);
	priv_key_template[j++] = makeCharArrayAttribute(CKA_ID, random_id, random_id_len);
	priv_key_template[j++] = makeUTF8Attribute(CKA_LABEL, gctx->label);

	if (!check_attributes_data(priv_key_template, j)) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE pub_key_handle;
	CK_OBJECT_HANDLE priv_key_handle;

	int ret;
	if ((ret = open_session(provctx, gctx->slot_id, &session_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err4;
	}

	if ((ret = user_login(provctx, gctx->pin)) != 0) {
		ERR_core_raise(handle, ret);
		goto err3;
	}

	if ((ret = PKCS11_HELPER_gen_keypair(method, session_handle, &mechanism, pub_key_template, i,
			priv_key_template, j, &pub_key_handle, &priv_key_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err3;
	}

	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);

	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *d = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *dmp1 = NULL;
	BIGNUM *dmq1 = NULL;
	BIGNUM *iqmp = NULL;

	if ((ret = PKCS11_HELPER_get_public_rsa_attributes(method, session_handle, pub_key_handle, &n, &e)) != 0) {
		ERR_core_raise(handle, ret);
		goto err3;
	}

	if (gctx->extractable) {
		if ((ret = PKCS11_HELPER_get_private_rsa_attributes(method, session_handle, priv_key_handle, &d, &p,
				&q, &dmp1, &dmq1, &iqmp)) != 0) {
			ERR_core_raise(handle, ret);
			goto err2;
		};
	}

	PKCS11_RSA_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_RSA_KEYDATA));
	if (!keydata) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}
	keydata->provctx = gctx->provctx;
	keydata->p11_handle = OPENSSL_zalloc(sizeof(PKCS11_PROV_KEY));
	if (!keydata->p11_handle) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	keydata->p11_handle->session_handle = session_handle;
	keydata->p11_handle->priv_key_handle = priv_key_handle;
	keydata->p11_handle->pub_key_handle = pub_key_handle;
	keydata->p11_handle->has_priv_key_handle = 1;
	keydata->p11_handle->has_pub_key_handle = 1;
	keydata->n = n;
	keydata->e = e;
	keydata->d = d;
	keydata->p = p;
	keydata->q = q;
	keydata->dmp1 = dmp1;
	keydata->dmq1 = dmq1;
	keydata->iqmp = iqmp;

	return keydata;
	
err0:
	OPENSSL_free(keydata);
err1:
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
err2:
	BN_free(n);
	BN_free(e);
err3:
	close_session(provctx, session_handle);
err4:
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);
	return NULL;
}

static void pkcs11_rsa_keymgmt_gen_cleanup(void *genctx)
{
	PKCS11_RSA_KEYMGMT_GEN_CTX *gctx = (PKCS11_RSA_KEYMGMT_GEN_CTX *) genctx;
	
	OPENSSL_clear_free(gctx->pin, strlen(gctx->pin) + 1);
	OPENSSL_free(gctx);
}

static void *pkcs11_rsa_keymgmt_load(const void *reference, size_t reference_sz)
{
	if (reference_sz != sizeof(PKCS11_KEY_REFERENCE))
		return NULL;
	
	// TODO check magic number
	
	PKCS11_KEY_REFERENCE *key_reference = (PKCS11_KEY_REFERENCE *) reference;

	CK_FUNCTION_LIST_PTR method = key_reference->provctx->method;
	PKCS11_PROV_CTX *provctx = key_reference->provctx;
	const OSSL_CORE_HANDLE *handle = provctx->core_handle;

	int ret;

	PKCS11_RSA_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_RSA_KEYDATA));
	if (!keydata) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err3;
	}

	keydata->p11_handle = OPENSSL_zalloc(sizeof(PKCS11_PROV_KEY));
		if (!keydata->p11_handle) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err2;
	}

	keydata->p11_handle->session_handle = key_reference->session_handle;
	if (key_reference->has_pub_key_handle) {
		keydata->p11_handle->pub_key_handle = key_reference->pub_key_handle;
		keydata->p11_handle->has_pub_key_handle = 1;
	}
	if (key_reference->has_priv_key_handle) {
		keydata->p11_handle->priv_key_handle = key_reference->priv_key_handle;
		keydata->p11_handle->has_priv_key_handle = 1;
	}

	BIGNUM *n = NULL;
	BIGNUM *e = NULL;

	CK_OBJECT_HANDLE default_handle = keydata->p11_handle->has_pub_key_handle
		? keydata->p11_handle->pub_key_handle
		: keydata->p11_handle->priv_key_handle;

	if ((ret = PKCS11_HELPER_get_public_rsa_attributes(method, keydata->p11_handle->session_handle,
			default_handle, &n, &e)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	};

	keydata->n = n;
	keydata->e = e;
	
	if ((ret = PKCS11_HELPER_get_obj_metadata(method, keydata->p11_handle->session_handle,
			default_handle, &keydata->label, NULL, NULL)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	};

	if (key_reference->has_priv_key_handle) {

		CK_BBOOL sensitive;
		if ((ret = PKCS11_HELPER_get_sensitive_attribute(method, keydata->p11_handle->session_handle,
				keydata->p11_handle->priv_key_handle, &sensitive)) != 0) {
			ERR_core_raise(handle, ret);
			goto err0;
		};

		if (!sensitive) {
			BIGNUM *d = NULL;
			BIGNUM *p = NULL;
			BIGNUM *q = NULL;
			BIGNUM *dmp1 = NULL;
			BIGNUM *dmq1 = NULL;
			BIGNUM *iqmp = NULL;

			if ((ret = PKCS11_HELPER_get_private_rsa_attributes(method, keydata->p11_handle->session_handle,
    				keydata->p11_handle->priv_key_handle, &d, &p, &q, &dmp1, &dmq1, &iqmp)) != 0) {
				ERR_core_raise(handle, ret);
				goto err0;
			}

			keydata->d = d;
			keydata->p = p;
			keydata->q = q;
			keydata->dmp1 = dmp1;
			keydata->dmq1 = dmq1;
			keydata->iqmp = iqmp;
		};
	}
	
	return keydata;

err0:
	BN_free(keydata->n);
	BN_free(keydata->e);
err1:
	OPENSSL_free(keydata->p11_handle);
err2:
	OPENSSL_free(keydata);
err3:
	close_session(provctx, key_reference->session_handle);
err4:
	return NULL;
}

static int pkcs11_rsa_keymgmt_has(const void *keydata, int selection)
{
	PKCS11_RSA_KEYDATA *key = (PKCS11_RSA_KEYDATA *) keydata;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (key->d == NULL || key->p == NULL || key->q == NULL ||
			key->dmp1 == NULL || key->dmq1 == NULL || key->iqmp == NULL) {
			return FALSE;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (key->n == NULL || key->e == NULL) {
			return FALSE;
		}
	} 
	
	if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		if (key->label == NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

int pkcs11_rsa_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
	PKCS11_RSA_KEYDATA *key1 = (PKCS11_RSA_KEYDATA *) keydata1;
	PKCS11_RSA_KEYDATA *key2 = (PKCS11_RSA_KEYDATA *) keydata2;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (BN_cmp(key1->d, key2->d) != 0 || BN_cmp(key1->p, key2->p) != 0 || BN_cmp(key1->q, key2->q) != 0 ||
			BN_cmp(key1->dmp1, key2->dmq1) != 0 || BN_cmp(key1->dmp1, key2->dmq1) != 0 ||
			BN_cmp(key1->iqmp, key2->iqmp) != 0) {
			return FALSE;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (BN_cmp(key1->n, key2->n) != 0 || BN_cmp(key1->e, key2->e) != 0) {
			return FALSE;
		}
	}
	
	if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		if (strcmp(key1->label, key2->label) != 0) {
			return FALSE;
		}
	}

	return TRUE;
}


static int pkcs11_rsa_keymgmt_import(void *keydata, int selection, const OSSL_PARAM *params)
{

	PKCS11_RSA_KEYDATA *key = (PKCS11_RSA_KEYDATA *) keydata;
	PKCS11_PROV_CTX *provctx = key->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;
	const OSSL_CORE_HANDLE *handle = key->provctx->core_handle;
		
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *d = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *dmp1 = NULL;
	BIGNUM *dmq1 = NULL;
	BIGNUM *iqmp = NULL;
	CK_BYTE *padded_n = NULL;
	CK_BYTE *e_bytes = NULL;
	CK_BYTE *padded_d = NULL;
	CK_BYTE *padded_p = NULL;
	CK_BYTE *padded_q = NULL;
	CK_BYTE *padded_dmp1 = NULL;
	CK_BYTE *padded_dmq1 = NULL;
	CK_BYTE *padded_iqmp = NULL;
	CK_ATTRIBUTE priv_key_template[32];
	CK_ATTRIBUTE pub_key_template[32];
	int i = 0, j = 0;
	const char *label = NULL;
	CK_SLOT_ID slot_id;
	int extractable = FALSE;
	const char *pin = NULL;

	int ret;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		const OSSL_PARAM *d_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
		const OSSL_PARAM *p_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
		const OSSL_PARAM *q_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
		const OSSL_PARAM *dmp1_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
		const OSSL_PARAM *dmq1_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
		const OSSL_PARAM *iqmp_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);


		if (!d_param || !p_param || !q_param) {
			ERR_core_raise(handle, MISSING_PRIVATE_KEY_PARAMETER);
			goto err1;
		}

		d = BN_bin2bn((unsigned char *) d_param->data, d_param->data_size, NULL);
		p = BN_bin2bn((unsigned char *) p_param->data, p_param->data_size, NULL);
		q = BN_bin2bn((unsigned char *) q_param->data, q_param->data_size, NULL);

		if (!d || !p || !q) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err1;
		}
		
		if (dmp1_param) {
			dmp1 = BN_bin2bn((unsigned char *) dmp1_param->data, dmp1_param->data_size, NULL);
			if (!dmp1) {
				ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
				goto err1;
			}
		}
		if (dmq1_param) {
			dmq1 = BN_bin2bn((unsigned char *) dmq1_param->data, dmq1_param->data_size, NULL);
			if (!dmq1) {
				ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
				goto err1;
			}
		}
		if (iqmp_param) {
			iqmp = BN_bin2bn((unsigned char *) iqmp_param->data, iqmp_param->data_size, NULL);
			if (!iqmp) {
				ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
				goto err1;
			}
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		const OSSL_PARAM *n_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
		const OSSL_PARAM *e_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);

		if (!n_param || !e_param) {
			ERR_core_raise(handle, MISSING_PUBLIC_KEY_PARAMETER);
			goto err1;
		}

		n = BN_bin2bn((unsigned char *) n_param->data, n_param->data_size, NULL);
		e = BN_bin2bn((unsigned char *) e_param->data, e_param->data_size, NULL);

		if (!n || !e) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err1;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		const OSSL_PARAM *label_param = OSSL_PARAM_locate_const(params, "label");
		const OSSL_PARAM *slot_id_param = OSSL_PARAM_locate_const(params, "slot-id");
		const OSSL_PARAM *pin_value_param = OSSL_PARAM_locate_const(params, "pin-value");
		const OSSL_PARAM *extractable_param = OSSL_PARAM_locate_const(params, "extractable");

		if (!label_param || !slot_id_param || !pin_value_param) {
			ERR_core_raise(handle, MISSING_KEY_OTHER_PARAMETER);
			goto err1;
		}

		label = label_param->data;

		if((ret = PKCS11_HELPER_slot_label_to_id(method, slot_id_param->data, &slot_id)) != 0) {
			ERR_core_raise(handle, INVALID_SLOT_ID);
			goto err1;
		};

		pin = pin_value_param->data;

		if (extractable_param) {
			extractable = *((int *) extractable_param->data);
		}
	}

	if ((!d || !p || !q) && (!n || !e)) {
		ERR_core_raise(handle, IMPORT_KEY_ERROR_INSUFFICIENT_KEY_MATERIAL);
		goto err1;
	}

	if (!label) {
		ERR_core_raise(handle, IMPORT_KEY_ERROR_MISSING_LABEL);
		goto err1;
	}

	if (!pin) {
		ERR_core_raise(handle, IMPORT_KEY_ERROR_MISSING_PIN);
		goto err1;
	}

	CK_SESSION_HANDLE session_handle;
	if ((ret = open_session(provctx, slot_id, &session_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	}

	if ((ret = user_login(provctx, pin)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	}

	if (!n || !e || !dmp1 || !dmq1 || !iqmp) {
		BN_CTX *bn_ctx = BN_CTX_new();

		if (!n && !e) {
			if ((ret = calculate_rsa_public_parameters(bn_ctx, d, p, q, &n, &e)) != 0){
				ERR_core_raise(handle, ret);
				BN_CTX_free(bn_ctx);
				goto err0;
			}
		}
		
		if (!dmp1 && !dmq1 && !iqmp && d && p && q) {
			if ((ret = calculate_rsa_crt_parameters(bn_ctx, d, p, q, &dmp1, &dmq1, &iqmp)) != 0) {
				ERR_core_raise(handle, ret);
				BN_CTX_free(bn_ctx);
				goto err0;
			}
		}

		BN_CTX_free(bn_ctx);
	}
	
	size_t n_len = BN_num_bytes(n);
	size_t e_bytes_len = BN_num_bytes(e);

	padded_n = OPENSSL_malloc(n_len);
	e_bytes = OPENSSL_malloc(e_bytes_len);

	if (!padded_n || !e_bytes) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}

	
	BN_bn2binpad(n, padded_n, n_len);
	BN_bn2bin(e, e_bytes);

	unsigned char random_id[20];
	RAND_bytes(random_id, sizeof(random_id));

	pub_key_template[i++] = makeObjectClassAttribute(CKA_CLASS, CKO_PUBLIC_KEY);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_TOKEN, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_MODIFIABLE, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_ENCRYPT, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_VERIFY, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_WRAP, CK_FALSE);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_MODULUS, padded_n, n_len);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_PUBLIC_EXPONENT, e_bytes, e_bytes_len);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_ID, random_id, sizeof(random_id));
	pub_key_template[i++] = makeUTF8Attribute(CKA_LABEL, label);

	if (!check_attributes_data(pub_key_template, i)) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}

	int has_priv_key = d && p && q && dmp1 && dmq1 && iqmp;

	if (has_priv_key) { // has private key material

		padded_d = OPENSSL_malloc(n_len);
		padded_p = OPENSSL_malloc(n_len / 2);
		padded_q = OPENSSL_malloc(n_len / 2);
		padded_dmp1 = OPENSSL_malloc(n_len / 2);
		padded_dmq1 = OPENSSL_malloc(n_len / 2);
		padded_iqmp = OPENSSL_malloc(n_len / 2);

		if (!padded_d || !padded_p || !padded_q || !padded_dmp1 || !padded_dmq1 || !padded_iqmp) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err0;
		}

		BN_bn2binpad(d, padded_d, n_len);
		BN_bn2binpad(p, padded_p, n_len / 2);
		BN_bn2binpad(q, padded_q, n_len / 2);
		BN_bn2binpad(dmp1, padded_dmp1, n_len / 2);
		BN_bn2binpad(dmq1, padded_dmq1, n_len / 2);
		BN_bn2binpad(iqmp, padded_iqmp, n_len / 2);

		priv_key_template[j++] = makeObjectClassAttribute(CKA_CLASS, CKO_PRIVATE_KEY);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_TOKEN, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_PRIVATE, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_MODIFIABLE, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_DECRYPT, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_SIGN, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_UNWRAP, CK_TRUE);
		priv_key_template[j++] = makeBooleanAttribute(CKA_SENSITIVE, !extractable);
		priv_key_template[j++] = makeBooleanAttribute(CKA_EXTRACTABLE, extractable);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_MODULUS, padded_n, n_len);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_PUBLIC_EXPONENT, e_bytes, e_bytes_len);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_PRIVATE_EXPONENT, padded_d, n_len);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_PRIME_1, padded_p, n_len / 2);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_PRIME_2, padded_q, n_len / 2);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_EXPONENT_1, padded_dmp1, n_len / 2);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_EXPONENT_2, padded_dmq1, n_len / 2);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_COEFFICIENT, padded_iqmp, n_len / 2);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_ID, random_id, sizeof(random_id));
		priv_key_template[j++] = makeUTF8Attribute(CKA_LABEL, label);

		if (!check_attributes_data(priv_key_template, j)) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err0;
		}
	}

	if ((ret = PKCS11_HELPER_create_object(method, session_handle, pub_key_template, i)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	}
	
	if (has_priv_key) {
		if ((ret = PKCS11_HELPER_create_object(method, session_handle, priv_key_template, j)) != 0) {
			ERR_core_raise(handle, ret);
			goto err0;
		}
	}

	CK_OBJECT_HANDLE priv_key_handle;
	CK_OBJECT_HANDLE pub_key_handle;

	/* We prefer the private handle because the private key contain both public and private info */
	if (has_priv_key) {
		if ((ret = PKCS11_HELPER_get_private_key_handle(method, session_handle, label, &priv_key_handle)) != 0) {
			ERR_core_raise(handle, ret);
			goto err0;
		}
	}
	
	if ((ret = PKCS11_HELPER_get_public_key_handle(method, session_handle, label, &pub_key_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	}

	key->p11_handle = OPENSSL_zalloc(sizeof(PKCS11_PROV_KEY));
	if (!key->p11_handle) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	key->p11_handle->session_handle = session_handle;
	if (has_priv_key) {
		key->p11_handle->priv_key_handle = priv_key_handle;
		key->p11_handle->has_priv_key_handle = 1;
	}
	key->p11_handle->pub_key_handle = pub_key_handle;
	key->p11_handle->has_pub_key_handle = 1;
	key->n = n;
	key->e = e;
	if (extractable) {
		key->d = d;
		key->p = p;
		key->q = q;
		key->dmp1 = dmp1;
		key->dmq1 = dmq1;
		key->iqmp = iqmp;
	} else {
		BN_clear_free(d);
		BN_clear_free(p);
		BN_clear_free(q);
		BN_clear_free(dmp1);
		BN_clear_free(dmq1);
		BN_clear_free(iqmp);
	}
	if (has_priv_key) key->is_priv = TRUE;
	key->extractable = extractable;
	key->label = OPENSSL_zalloc(strlen(label) + 1);
	if (!key->label) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	OPENSSL_strlcpy(key->label, label, strlen(label) + 1);

	OPENSSL_free(padded_n);
	OPENSSL_free(e_bytes);
	OPENSSL_clear_free(padded_d, n_len);
	OPENSSL_clear_free(padded_p, n_len / 2);
	OPENSSL_clear_free(padded_q, n_len / 2);
	OPENSSL_clear_free(padded_dmp1, n_len / 2);
	OPENSSL_clear_free(padded_dmq1, n_len / 2);
	OPENSSL_clear_free(padded_iqmp, n_len / 2);
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);

	return TRUE;

err0:
	close_session(provctx, session_handle);
err1:
	BN_free(n);
	BN_free(e);
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	OPENSSL_free(padded_n);
	OPENSSL_free(e_bytes);
	OPENSSL_clear_free(padded_d, n_len);
	OPENSSL_clear_free(padded_p, n_len / 2);
	OPENSSL_clear_free(padded_q, n_len / 2);
	OPENSSL_clear_free(padded_dmp1, n_len / 2);
	OPENSSL_clear_free(padded_dmq1, n_len / 2);
	OPENSSL_clear_free(padded_iqmp, n_len / 2);
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);

	return FALSE;
}

static const OSSL_PARAM *pkcs11_rsa_keymgmt_import_types(int selection)
{
	static const OSSL_PARAM private_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM public_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM domain_params[] = {
		OSSL_PARAM_END
	};
	static const OSSL_PARAM other_params[] = {
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_utf8_string("pin-value", NULL, 0),
		OSSL_PARAM_utf8_string("slot-id", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_parameters_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_utf8_string("pin-value", NULL, 0),
		OSSL_PARAM_utf8_string("slot-id", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM keypair_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_utf8_string("pin-value", NULL, 0),
		OSSL_PARAM_utf8_string("slot-id", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};

	if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		return private_key_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		return public_key_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		return domain_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		return other_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_KEYPAIR) {
		return keypair_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
		return all_parameters_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_ALL) {
		return all_params;
	}

	return NULL;
}

static int pkcs11_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
	PKCS11_RSA_KEYDATA *key = (PKCS11_RSA_KEYDATA *) keydata;
	const OSSL_CORE_HANDLE *handle = key->provctx->core_handle;

	OSSL_PARAM_BLD *param_builder = OSSL_PARAM_BLD_new();
	if (!param_builder) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (key->d) {
			if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_D, key->d) ||
				!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_FACTOR1, key->p) ||
				!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_FACTOR2, key->q) ||
				!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_EXPONENT1, key->dmp1) ||
				!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_EXPONENT2, key->dmq1) ||
				!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, key->iqmp)) {
				ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
				goto err1;
			}
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_N, key->n) ||
			!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_E, key->e)) {
			ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
			goto err1;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		if (!OSSL_PARAM_BLD_push_utf8_string(param_builder, "label", key->label, strlen(key->label)) ||
			!OSSL_PARAM_BLD_push_int(param_builder, "extractable", key->extractable)) {
			ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
			goto err1;
		}
	}

	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_builder);
	if (!params) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}

	if (!param_cb(params, cbarg)) {
		ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
		goto err0;
	}

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(param_builder);

	return TRUE;

err0:
	OSSL_PARAM_free(params);
err1:
	OSSL_PARAM_BLD_free(param_builder);
	
	return FALSE;
}

static const OSSL_PARAM * pkcs11_rsa_keymgmt_export_types(int selection)
{
	static const OSSL_PARAM private_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM public_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM domain_params[] = {
		OSSL_PARAM_END
	};
	static const OSSL_PARAM other_params[] = {
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_parameters_params[] = {
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM keypair_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};

	if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		return private_key_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		return public_key_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		return domain_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		return other_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_KEYPAIR) {
		return keypair_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
		return all_parameters_params;
	} else if (selection == OSSL_KEYMGMT_SELECT_ALL) {
		return all_params;
	}

	return NULL;
}

const OSSL_DISPATCH pkcs11_rsa_keymgmt_fns[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) pkcs11_rsa_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) pkcs11_rsa_keymgmt_free},
	{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) pkcs11_rsa_keymgmt_gen_init},
	{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) pkcs11_rsa_keymgmt_gen_set_params},
	{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) pkcs11_rsa_keymgmt_gen_settable_params},
	{OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) pkcs11_rsa_keymgmt_gen},
	{OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) pkcs11_rsa_keymgmt_gen_cleanup},
	{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) pkcs11_rsa_keymgmt_load},
	{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) pkcs11_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) pkcs11_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) pkcs11_rsa_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) pkcs11_rsa_keymgmt_export},
	{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) pkcs11_rsa_keymgmt_export_types},
    {0, NULL}
};