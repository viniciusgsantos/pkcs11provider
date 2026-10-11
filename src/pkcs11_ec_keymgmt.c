#include "pkcs11provider/pkcs11_ec_keymgmt.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_attr.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_store.h"
#include "pkcs11provider/pkcs11_types.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <string.h>

static void *pkcs11_ec_keymgmt_new(void *provctx)
{
	PKCS11_EC_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_EC_KEYDATA));
	keydata->provctx = (PKCS11_PROV_CTX *) provctx;
	return keydata;
}

static void pkcs11_ec_keymgmt_free(void *keydata)
{
	PKCS11_EC_KEYDATA *key = (PKCS11_EC_KEYDATA *) keydata;
	if (key) {
		BN_free(key->pub_x);
		BN_free(key->pub_y);
		BN_clear_free(key->priv);
		OPENSSL_free(key->label);
		OPENSSL_free(key);
	}
}

static void *pkcs11_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM *params)
{
	PKCS11_EC_KEYMGMT_GEN_CTX *genctx = OPENSSL_zalloc(sizeof(PKCS11_EC_KEYMGMT_GEN_CTX));
	genctx->provctx = (PKCS11_PROV_CTX *) provctx;
	CK_FUNCTION_LIST_PTR method = genctx->provctx->method;
	const OSSL_CORE_HANDLE *handle = genctx->provctx->core_handle;

	if (params) {
		int i;
		for (i = 0; params[i].key != NULL; i++) {
			if (strcmp(params[i].key, OSSL_PKEY_PARAM_GROUP_NAME) == 0) {
				int curve_nid = curveName2nid((const char *) params[i].data);
				if (curve_nid == NID_undef) {
					ERR_core_raise(handle, UNKNOWN_CURVE_NAME);
					return FALSE;
				}
				genctx->curve_name = curveNid2Name(curve_nid);
			} else if (strcmp(params[i].key, "slot-id") == 0) {
				unsigned char *slot_id_arg = OPENSSL_malloc(params[i].data_size + 1);
				if (!slot_id_arg) {
					ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
					return FALSE;
				}
				OPENSSL_strlcpy(slot_id_arg, params[i].data, params[i].data_size + 1);
				if (PKCS11_HELPER_slot_label_to_id(method, slot_id_arg, &genctx->slot_id) != 0) {
					ERR_core_raise(handle, SLOT_ID_PARSING_ERROR);
					OPENSSL_free(slot_id_arg);
					return FALSE;
				}
				OPENSSL_free(slot_id_arg);
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
			}
		}
	}

	return genctx;
}

static int pkcs11_ec_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM *params)
{
	PKCS11_EC_KEYMGMT_GEN_CTX *gctx = (PKCS11_EC_KEYMGMT_GEN_CTX *) genctx;
	CK_FUNCTION_LIST_PTR method = gctx->provctx->method;
	const OSSL_CORE_HANDLE *handle = gctx->provctx->core_handle;

	if (params) {
		int i;
		for (i = 0; params[i].key != NULL; i++) {
			if (strcmp(params[i].key, OSSL_PKEY_PARAM_GROUP_NAME) == 0) {
				int curve_nid = curveName2nid((const char *) params[i].data);
				if (curve_nid == NID_undef) {
					ERR_core_raise(handle, UNKNOWN_CURVE_NAME);
					return FALSE;
				}
				gctx->curve_name = curveNid2Name(curve_nid);
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
				gctx->extractable = *( int *) params[i].data;
			}
		}
	}

	return TRUE;
}

static const OSSL_PARAM *pkcs11_ec_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
	static const OSSL_PARAM gen_settable_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_utf8_string("slot-id", NULL, 0),
		OSSL_PARAM_utf8_string("pin-value", NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};

	return gen_settable_params;
}

static void *pkcs11_ec_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
	PKCS11_EC_KEYMGMT_GEN_CTX *gctx = (PKCS11_EC_KEYMGMT_GEN_CTX *) genctx;
	CK_FUNCTION_LIST_PTR method = gctx->provctx->method;
	const OSSL_CORE_HANDLE *handle = gctx->provctx->core_handle;

	CK_MECHANISM mechanism;
	mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	CK_BYTE *curve_param = NULL;
	int curve_size = curveName2P11Curve(gctx->curve_name, &curve_param);

	size_t random_id_len = 20;
	unsigned char random_id[random_id_len];
	RAND_bytes(random_id, sizeof(random_id));

	CK_ATTRIBUTE pub_key_template[32];
	CK_ATTRIBUTE priv_key_template[32];

	int i = 0, j = 0;
	pub_key_template[i++] = makeObjectClassAttribute(CKA_CLASS, CKO_PUBLIC_KEY);
	pub_key_template[i++] = makeBooleanAttribute(CKA_TOKEN, CK_TRUE);
	//pub_key_template[i++] = makeBooleanAttribute(CKA_PRIVATE, FALSE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_MODIFIABLE, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_ENCRYPT, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_VERIFY, CK_TRUE);
	pub_key_template[i++] = makeBooleanAttribute(CKA_WRAP, CK_TRUE);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_EC_PARAMS, curve_param, curve_size);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_ID, random_id, random_id_len);
	pub_key_template[i++] = makeUTF8Attribute(CKA_LABEL, gctx->label);

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
	
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE pub_key_handle;
	CK_OBJECT_HANDLE priv_key_handle;
	
	int ret;
	if ((ret = PKCS11_HELPER_open_session(method, gctx->slot_id, &session_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err4;
	}

	if((ret = PKCS11_HELPER_login(method, session_handle, gctx->pin)) != 0) {
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
	
	BIGNUM *pub_x = NULL;
	BIGNUM *pub_y = NULL;
	BIGNUM *priv = NULL;
	const char *curve_name;

	if ((ret = PKCS11_HELPER_get_public_ec_attributes(method, session_handle, pub_key_handle, &pub_x, &pub_y)) != 0) {
		ERR_core_raise(handle, ret);
		goto err3;
	}

	if (gctx->extractable) {
		if ((ret = PKCS11_HELPER_get_private_ec_attributes(method, session_handle, priv_key_handle, &priv)) != 0) {
			ERR_core_raise(handle, ret);
			goto err2;
		}
	}

	if ((ret = PKCS11_HELPER_get_ec_curve_name(method, session_handle, pub_key_handle, &curve_name)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	}

	PKCS11_EC_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_EC_KEYDATA));
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
	keydata->p11_handle->has_pub_key_handle = 1;
	keydata->p11_handle->has_priv_key_handle = 1;
	keydata->curve_name = curve_name;
	keydata->pub_x = pub_x;
	keydata->pub_y = pub_y;
	keydata->priv = priv;

	return keydata;

err0:
	OPENSSL_free(keydata);
err1:
	BN_clear_free(priv);
err2:
	BN_free(pub_x);
	BN_free(pub_y);
err3:
	PKCS11_HELPER_close_session(method, session_handle);
err4:
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);
	return NULL;
}

static void pkcs11_ec_keymgmt_gen_cleanup(void *genctx)
{
	PKCS11_EC_KEYMGMT_GEN_CTX *gctx = (PKCS11_EC_KEYMGMT_GEN_CTX *) genctx;
	if (gctx) {
		OPENSSL_clear_free(gctx->pin, strlen(gctx->pin) + 1);
		OPENSSL_free(gctx->label);
		OPENSSL_free(gctx);
	}
}

static void *pkcs11_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
	if (reference_sz != sizeof(PKCS11_KEY_REFERENCE))
		return NULL;
	
	// TODO check magic number
	
	PKCS11_KEY_REFERENCE *key_reference = (PKCS11_KEY_REFERENCE *) reference;

	CK_FUNCTION_LIST_PTR method = key_reference->provctx->method;
	const OSSL_CORE_HANDLE *handle = key_reference->provctx->core_handle;

	int ret;

	PKCS11_EC_KEYDATA *keydata = OPENSSL_zalloc(sizeof(PKCS11_EC_KEYDATA));
	if (!keydata) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err3;
	}

	keydata->p11_handle = OPENSSL_zalloc(sizeof(PKCS11_PROV_KEY));
		if (!keydata->p11_handle) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err2;
	}

	if (key_reference->has_pub_key_handle) {
		keydata->p11_handle->pub_key_handle = key_reference->pub_key_handle;
		keydata->p11_handle->has_pub_key_handle = 1;
	}
	if (key_reference->has_priv_key_handle) {
		keydata->p11_handle->priv_key_handle = key_reference->priv_key_handle;
		keydata->p11_handle->has_priv_key_handle = 1;
	}
	keydata->p11_handle->session_handle = key_reference->session_handle;

	BIGNUM *pub_x = NULL;
	BIGNUM *pub_y = NULL;

	if ((ret = PKCS11_HELPER_get_public_ec_attributes(method, keydata->p11_handle->session_handle,
			keydata->p11_handle->pub_key_handle, &pub_x, &pub_y)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	};

	keydata->pub_x = pub_x;
	keydata->pub_y = pub_y;
	const char *curve_name = NULL;

	CK_OBJECT_HANDLE default_handle = keydata->p11_handle->has_pub_key_handle
		? keydata->p11_handle->pub_key_handle
		: keydata->p11_handle->priv_key_handle;

	if ((ret = PKCS11_HELPER_get_obj_metadata(method, keydata->p11_handle->session_handle,
			keydata->p11_handle->pub_key_handle, &keydata->label, NULL, NULL)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	};

	if (keydata->p11_handle->has_priv_key_handle) {

		CK_BBOOL sensitive;
		if ((ret = PKCS11_HELPER_get_sensitive_attribute(method, keydata->p11_handle->session_handle,
				keydata->p11_handle->priv_key_handle, &sensitive)) != 0) {
			ERR_core_raise(handle, ret);
			goto err0;
		};

		if (!sensitive) {
			BIGNUM *priv = NULL;
			if ((ret = PKCS11_HELPER_get_private_ec_attributes(method, keydata->p11_handle->session_handle,
    				keydata->p11_handle->priv_key_handle, &priv)) != 0) {
				ERR_core_raise(handle, ret);
				goto err0;
			}

			keydata->priv = priv;
		};
	}

	if ((ret = PKCS11_HELPER_get_ec_curve_name(method, keydata->p11_handle->session_handle,
		default_handle, &curve_name)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	}

	keydata->curve_name = curve_name;
	
	return keydata;

err0:
	BN_free(keydata->pub_x);
	BN_free(keydata->pub_y);
err1:
	OPENSSL_free(keydata->p11_handle);
err2:
	OPENSSL_free(keydata);
err3:
	PKCS11_HELPER_close_session(method, key_reference->session_handle);
err4:
	return NULL;
}

static int pkcs11_ec_keymgmt_has(const void *keydata, int selection)
{
	PKCS11_EC_KEYDATA *key = (PKCS11_EC_KEYDATA *) keydata;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (!key->is_priv) {
			return FALSE;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (key->pub_x == NULL || key->pub_y == NULL) {
			return FALSE;
		}
	}

		if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		if (strlen(key->curve_name) == 0) {
			return FALSE;
		}
	}
	
	if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
		if (strlen(key->label) == 0) {
			return FALSE;
		}
	}

	return TRUE;
}

int pkcs11_ec_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
	PKCS11_EC_KEYDATA *key1 = (PKCS11_EC_KEYDATA *) keydata1;
	PKCS11_EC_KEYDATA *key2 = (PKCS11_EC_KEYDATA *) keydata2;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (BN_cmp(key1->priv, key2->priv) != 0) {
			return FALSE;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (BN_cmp(key1->pub_x, key2->pub_x) != 0 || BN_cmp(key1->pub_y, key2->pub_y) != 0) {
			return FALSE;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		if (strcmp(key1->curve_name, key2->curve_name) != 0) {
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

static int pkcs11_ec_keymgmt_import(void *keydata, int selection, const OSSL_PARAM *params)
{
	PKCS11_EC_KEYDATA *key = (PKCS11_EC_KEYDATA *) keydata;
	CK_FUNCTION_LIST_PTR method = key->provctx->method;
	const OSSL_CORE_HANDLE *handle = key->provctx->core_handle;
	
	BIGNUM *pub_x = NULL;
	BIGNUM *pub_y = NULL;
	BIGNUM *priv = NULL;
	EC_GROUP *ec_group = NULL;
	EC_POINT *ec_p = NULL;
	CK_ATTRIBUTE priv_key_template[32];
	CK_ATTRIBUTE pub_key_template[32];
	int i = 0, j = 0;
	unsigned char *der_encoded_curve_oid = NULL;
	size_t der_encoded_curve_oid_len = 0;
	unsigned char *encoded_point = NULL;
	ASN1_OCTET_STRING *asn1_encoded_point = NULL;
	unsigned char *der_encoded_point = NULL;
	int curve_nid;
	const char *label = NULL;
	CK_SLOT_ID slot_id;
	int extractable = FALSE;
	const char *pin = NULL;

	int ret;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		const OSSL_PARAM *priv_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
		if (!priv_param) {
			ERR_core_raise(handle, MISSING_PRIVATE_KEY_PARAMETER);
			goto err1;
		}

		priv = BN_bin2bn((unsigned char *) priv_param->data, priv_param->data_size, NULL);

		if (!priv) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err1;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		const OSSL_PARAM *pub_x_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_PUB_X);
		const OSSL_PARAM *pub_y_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_PUB_Y);

		if (!pub_x_param || !pub_y_param) {
			ERR_core_raise(handle, MISSING_PUBLIC_KEY_PARAMETER);
			goto err1;
		}

		pub_x = BN_bin2bn((unsigned char *) pub_x_param->data, pub_x_param->data_size, NULL);
		pub_y = BN_bin2bn((unsigned char *) pub_y_param->data, pub_y_param->data_size, NULL);

		if (!pub_x || !pub_y) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err1;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		const OSSL_PARAM *group_name_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);

		if (!group_name_param) {
			ERR_core_raise(handle, MISSING_KEY_DOMAIN_PARAMETER);
			goto err1;
		}

		curve_nid = curveName2nid(group_name_param[0].data);
		if (curve_nid == NID_undef) {
			ERR_core_raise(handle, UNKNOWN_CURVE_NAME);
			goto err1;
		}
		der_encoded_curve_oid_len = curveName2P11Curve(group_name_param[0].data, &der_encoded_curve_oid);
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

	if (!priv && (!pub_x || !pub_y)) {
		ERR_core_raise(handle, IMPORT_KEY_ERROR_INSUFFICIENT_KEY_MATERIAL);
		goto err1;
	}

	if (curve_nid == NID_undef) {
		ERR_core_raise(handle, IMPORT_KEY_ERROR_MISSING_CURVE_NAME);
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

	// We are logging in early to fail early in case of incorrect pin or slot id.
	CK_SESSION_HANDLE session_handle;
	if ((ret = PKCS11_HELPER_open_session(method, slot_id, &session_handle)) != 0) {
		ERR_core_raise(handle, ret);
		goto err1;
	}

	if ((ret = PKCS11_HELPER_login(method, session_handle, pin)) != 0) {
		ERR_core_raise(handle, ret);
		goto err0;
	}

	ec_group = EC_GROUP_new_by_curve_name(curve_nid);
	if (!ec_group) {
		ERR_core_raise(handle, EC_CURVE_PARSING_ERROR);
		goto err0;
	}

	ec_p = EC_POINT_new(ec_group);

	if (!pub_x && !pub_y) {
		/* Derive public parameters from private key */
		BN_CTX *bn_ctx = BN_CTX_new();
		if (EC_POINT_mul(ec_group, ec_p, priv, NULL, NULL, bn_ctx) == 0) {
			ERR_core_raise(handle, EC_PUBLIC_PARAMETERS_CALCULATION_ERROR);
			BN_CTX_free(bn_ctx);
			goto err0;
		}

		pub_x = BN_new();
		pub_y = BN_new();
		if (!pub_x || !pub_y) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			BN_CTX_free(bn_ctx);
			goto err0;
		}

		if (EC_POINT_get_affine_coordinates(ec_group, ec_p, pub_x, pub_y, bn_ctx) == 0) {
			ERR_core_raise(handle, EC_PUBLIC_PARAMETERS_CALCULATION_ERROR);
			BN_CTX_free(bn_ctx);
			goto err0;
		}

		BN_CTX_free(bn_ctx);
	} else {
		if (EC_POINT_set_affine_coordinates(ec_group, ec_p, pub_x, pub_y, NULL) == 0) {
			ERR_core_raise(handle, EC_CURVE_PARSING_ERROR);
			goto err0;
		}
	}

	size_t encoded_point_len = EC_POINT_point2oct(ec_group, ec_p, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	encoded_point = OPENSSL_malloc(encoded_point_len); 
	if (!encoded_point) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	EC_POINT_point2oct(ec_group, ec_p, POINT_CONVERSION_UNCOMPRESSED, encoded_point, encoded_point_len, NULL);

	asn1_encoded_point = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(asn1_encoded_point, encoded_point, encoded_point_len);
	size_t der_encoded_point_len = i2d_ASN1_OCTET_STRING(asn1_encoded_point, &der_encoded_point);

	unsigned char key_id[EVP_MAX_MD_SIZE];
	int key_id_len = 0;
	calculate_sha1_digest(encoded_point, encoded_point_len, key_id, &key_id_len);

	pub_key_template[i++] = makeObjectClassAttribute(CKA_CLASS, CKO_PUBLIC_KEY);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_TOKEN, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_MODIFIABLE, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_ENCRYPT, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_VERIFY, CK_TRUE);
	pub_key_template[i++] = makeUnsignedLongAttribute(CKA_WRAP, CK_FALSE);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_EC_PARAMS,
		der_encoded_curve_oid, der_encoded_curve_oid_len);
	pub_key_template[i++] = toCharArrayAttribute(CKA_EC_POINT, &der_encoded_point, der_encoded_point_len);
	pub_key_template[i++] = makeCharArrayAttribute(CKA_ID, key_id, key_id_len);
	pub_key_template[i++] = makeUTF8Attribute(CKA_LABEL, label);

	if (!check_attributes_data(pub_key_template, i)) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}

	int has_priv_key = priv != NULL;

	if (has_priv_key) {

		int n_len = (EC_GROUP_order_bits(ec_group) + 7) / 8;

		unsigned char *priv_attr = OPENSSL_zalloc(n_len);
		if (!priv_attr) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err0;
		}

		if (BN_bn2binpad(priv, priv_attr, n_len) <= 0) {
			ERR_core_raise(handle, EC_PRIV_VALUE_PARSING_ERROR);
			OPENSSL_clear_free(priv_attr, n_len);
			goto err0;
		}

		priv_key_template[j++] = makeObjectClassAttribute(CKA_CLASS, CKO_PRIVATE_KEY);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_TOKEN, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_PRIVATE, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_MODIFIABLE, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_DECRYPT, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_SIGN, CK_TRUE);
		priv_key_template[j++] = makeUnsignedLongAttribute(CKA_UNWRAP, CK_FALSE);
		priv_key_template[j++] = makeBooleanAttribute(CKA_SENSITIVE, !extractable);
		priv_key_template[j++] = makeBooleanAttribute(CKA_EXTRACTABLE, extractable);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_EC_PARAMS,
			der_encoded_curve_oid, der_encoded_curve_oid_len);
		priv_key_template[j++] = toCharArrayAttribute(CKA_VALUE, &priv_attr, n_len);
		priv_key_template[j++] = makeCharArrayAttribute(CKA_ID, key_id, key_id_len);
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
	key->curve_name = OBJ_nid2sn(curve_nid);
	key->pub_x = pub_x;
	key->pub_y = pub_y;
	if (extractable) {
		key->priv = priv;
	} else {
		BN_clear_free(priv);
	}
	if (has_priv_key) key->is_priv = TRUE;
	key->extractable = extractable;
	key->label = OPENSSL_zalloc(strlen(label) + 1);
	if (!key->label) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	OPENSSL_strlcpy(key->label, label, strlen(label) + 1);
	
	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_p);
	OPENSSL_free(encoded_point);
	ASN1_OCTET_STRING_free(asn1_encoded_point);
	OPENSSL_free(der_encoded_curve_oid);
	OPENSSL_free(der_encoded_point);
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);

	return TRUE;

err0:
	PKCS11_HELPER_close_session(method, session_handle);
err1:
	BN_free(pub_x);
	BN_free(pub_y);
	BN_clear_free(priv);
	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_p);
	OPENSSL_free(encoded_point);
	OPENSSL_free(der_encoded_curve_oid);
	OPENSSL_free(der_encoded_point);
	ASN1_OCTET_STRING_free(asn1_encoded_point);
	free_attributes_data(pub_key_template, i);
	free_attributes_data(priv_key_template, j);

	return FALSE;
}

static const OSSL_PARAM *pkcs11_ec_keymgmt_import_types(int selection)
{
	static const OSSL_PARAM private_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM public_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM domain_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
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
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
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

static int pkcs11_ec_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
	PKCS11_EC_KEYDATA *key = (PKCS11_EC_KEYDATA *) keydata;
	const OSSL_CORE_HANDLE *handle = key->provctx->core_handle;

	OSSL_PARAM_BLD *param_builder = OSSL_PARAM_BLD_new();
	if (!param_builder) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (key->priv) {
			if(!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PRIV_KEY, key->priv)) {
				ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
				goto err1;
			}
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_EC_PUB_X, key->pub_x) ||
			!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_EC_PUB_Y, key->pub_y)) {
			ERR_core_raise(handle, KEY_PARAMETER_EXPORTATION_ERROR);
			goto err1;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		if (!OSSL_PARAM_BLD_push_utf8_string(param_builder, OSSL_PKEY_PARAM_GROUP_NAME,
				key->curve_name, strlen(key->curve_name))) {
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

static const OSSL_PARAM * pkcs11_ec_keymgmt_export_types(int selection) {
	static const OSSL_PARAM private_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM public_key_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM domain_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM other_params[] = {
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_parameters_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_utf8_string("label", NULL, 0),
		OSSL_PARAM_int("extractable", NULL),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM keypair_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_END
	};
	static const OSSL_PARAM all_params[] = {
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
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

const OSSL_DISPATCH pkcs11_ec_keymgmt_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) pkcs11_ec_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) pkcs11_ec_keymgmt_free },
	{ OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) pkcs11_ec_keymgmt_gen_init },
	{ OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) pkcs11_ec_keymgmt_gen_set_params },
	{ OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) pkcs11_ec_keymgmt_gen_settable_params },
	{ OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) pkcs11_ec_keymgmt_gen },
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) pkcs11_ec_keymgmt_gen_cleanup },
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) pkcs11_ec_keymgmt_load },
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) pkcs11_ec_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) pkcs11_ec_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) pkcs11_ec_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) pkcs11_ec_keymgmt_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) pkcs11_ec_keymgmt_export_types },
    {0, NULL}
};