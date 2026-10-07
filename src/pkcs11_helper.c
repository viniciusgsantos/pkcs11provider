#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_attr.h"
#include "pkcs11provider/pkcs11/pkcs11.h"


#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <ctype.h>

int PKCS11_HELPER_initialize(CK_FUNCTION_LIST_PTR method, const char *init_args)
{
	CK_RV rv;
	int locking = 0;

	rv = method->C_Initialize(NULL_PTR);

	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		method->C_Finalize(NULL_PTR); // not checking on purpose
		rv = method->C_Initialize(NULL_PTR);
	}
	
	if (rv != CKR_OK) {
		return rv;
	}

	return 0;
}

int PKCS11_HELPER_open_session(CK_FUNCTION_LIST_PTR method,
		const CK_SLOT_ID slot_id, CK_SESSION_HANDLE *session_handle)
{
	CK_RV rv = method->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, session_handle);

	if (rv != CKR_OK)
		return rv;

	return 0;
}

// TODO implement a global login
int PKCS11_HELPER_login(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
		const char *user_pin)
{
	CK_RV rv = method->C_Login(session_handle, CKU_USER, (unsigned char *)user_pin, strlen(user_pin));
	
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		return rv;
	
	return 0;
}
int PKCS11_HELPER_logout(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = method->C_Logout(session_handle);

	if(rv != CKR_OK)
		return rv;

	return 0;
}

int PKCS11_HELPER_close_session(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = method->C_CloseSession(session_handle);

	if(rv != CKR_OK)
		return rv;

	return 0;
}

static int PKCS11_HELPER_get_key_handle(CK_FUNCTION_LIST_PTR method,
		const CK_SESSION_HANDLE session_handle,
		const char *key_label, int isPrivate,
		CK_OBJECT_HANDLE *object)
{
	int ret;
	int objectNotFound = 0;
	CK_OBJECT_CLASS keyClass;
	keyClass = isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;

	CK_ATTRIBUTE tmpl[] = {
			{ CKA_CLASS, &keyClass, sizeof(keyClass) },
			{ CKA_LABEL, (char *) key_label, strlen(key_label) }
	};

	ret = method->C_FindObjectsInit(session_handle, tmpl, 2);
	if (ret != CKR_OK){
		goto err1;
	}

	CK_ULONG object_count;

	// Get the first occurrence
	ret = method->C_FindObjects(session_handle, object, 1, &object_count);
	if (ret != CKR_OK)
		goto err0;
	if (object_count == 0) {
		ret = PKCS11_NO_SUCH_KEY;
		goto err0;
	}

	ret = method->C_FindObjectsFinal(session_handle);
	if (ret != CKR_OK){
		goto err1;
	}

	return 0;

err0:
	method->C_FindObjectsFinal(session_handle); // No error checking, we are exiting anyway
err1:
	return ret;
}

int PKCS11_HELPER_get_public_key_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
	const char *key_label, CK_OBJECT_HANDLE *object)
{
	return PKCS11_HELPER_get_key_handle(method, session_handle, key_label, FALSE, object);
}

int PKCS11_HELPER_get_private_key_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
	const char *key_label, CK_OBJECT_HANDLE *object)
{
	return PKCS11_HELPER_get_key_handle(method, session_handle, key_label, TRUE, object);
}

int PKCS11_HELPER_get_obj_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
    const char *alias, CK_OBJECT_HANDLE *obj_handle, CK_OBJECT_CLASS *class)
{
	int ret;
	int objectNotFound = 0;
	char alias_arg[strlen(alias) + 1];
	strcpy(alias_arg, alias);

	CK_ATTRIBUTE tmpl[] = {
			{ CKA_LABEL, alias_arg, strlen(alias_arg) }
	};

	ret = method->C_FindObjectsInit(session_handle, tmpl, SIZEOF_ARRAY(tmpl));
	if (ret != CKR_OK)
		goto err1;

	CK_ULONG object_count;

	// Get the first occurrence
	ret = method->C_FindObjects(session_handle, obj_handle, 1, &object_count);
	if (ret != CKR_OK)
		goto err0;
	if (object_count == 0) {
		ret = PKCS11_NO_SUCH_KEY;
		goto err0;
	}

	ret = method->C_FindObjectsFinal(session_handle);
	if (ret != CKR_OK){
		goto err1;
	}

	if (class) {
		int rv;
		CK_KEY_TYPE obj_class;

		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &obj_class, sizeof(CK_KEY_TYPE)},
		};

		rv = method->C_GetAttributeValue(session_handle, *obj_handle, tmpl, SIZEOF_ARRAY(tmpl));
		if (rv != CKR_OK)
			goto err1;
		
		*class = obj_class;
	}

	return 0;

err0:
	method->C_FindObjectsFinal(session_handle); // No error checking, we are exiting anyway
err1:
	return ret;
}

int PKCS11_HELPER_find_obj_by_label_init(CK_FUNCTION_LIST_PTR method,
											const CK_SESSION_HANDLE session_handle,
    										const char *label)
{
	int ret;
	unsigned char *label_arg = (unsigned char *)(uintptr_t) label;

	CK_ATTRIBUTE tmpl[] = {
		{ CKA_LABEL, label_arg, strlen(label_arg) }
	};

	return method->C_FindObjectsInit(session_handle, tmpl, SIZEOF_ARRAY(tmpl));
}

int PKCS11_HELPER_find_obj(CK_FUNCTION_LIST_PTR method,
							   const CK_SESSION_HANDLE session_handle,
							   CK_OBJECT_HANDLE *obj_handle,
							   CK_ULONG_PTR obj_count)
{
	int ret;
	CK_ULONG pulObjectCount = *obj_count;

	ret = method->C_FindObjects(session_handle, obj_handle, *obj_count, &pulObjectCount);
	
	if (ret != CKR_OK)
		return ret;

	*obj_count = pulObjectCount;

	return 0;
}

int PKCS11_HELPER_find_obj_final(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle)
{
	return method->C_FindObjectsFinal(session_handle);
}

int PKCS11_HELPER_get_obj_class(CK_FUNCTION_LIST_PTR method,
									const CK_SESSION_HANDLE session_handle,
                                    const CK_OBJECT_HANDLE obj_handle,
                                    CK_OBJECT_CLASS *obj_class)
{	
	int ret;
	CK_OBJECT_CLASS obj_class_attr;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &obj_class_attr, sizeof(CK_OBJECT_CLASS)},
	};

	ret = method->C_GetAttributeValue(session_handle, obj_handle, tmpl, SIZEOF_ARRAY(tmpl));
	
	if (ret != CKR_OK)
		return ret;
	
	*obj_class = obj_class_attr;

	return 0;
}

int PKCS11_HELPER_gen_keypair(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
	CK_MECHANISM *mechanism,
	CK_ATTRIBUTE_PTR pubKeyAttributes, unsigned long pubKeyAttributesLen,
	CK_ATTRIBUTE_PTR privKeyAttributes, unsigned long privKeyAttributesLen,
	CK_OBJECT_HANDLE *pub_key_handle, CK_OBJECT_HANDLE *priv_key_handle)
{
	CK_RV rv;
	CK_OBJECT_HANDLE pub_key_handle_arg;
	CK_OBJECT_HANDLE priv_key_handle_arg;
	rv = method->C_GenerateKeyPair(session_handle, mechanism, pubKeyAttributes, pubKeyAttributesLen,
		privKeyAttributes, privKeyAttributesLen,
		&pub_key_handle_arg, &priv_key_handle_arg);
	
	if (rv != CKR_OK)
		return rv;
	
	*pub_key_handle = pub_key_handle_arg;
	*priv_key_handle = priv_key_handle_arg;

	return 0;
}

int PKCS11_HELPER_create_object(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_size)
{
	CK_OBJECT_HANDLE newObject;
	int i = 0;
	CK_RV rv = method->C_CreateObject(session_handle, tmpl, tmpl_size, &newObject);
	
	if (rv != CKR_OK)
		return rv;
	
	return 0;
}

int PKCS11_HELPER_get_public_ec_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **pub_x, BIGNUM **pub_y)
{
	int rv;

	CK_ATTRIBUTE pub_tmpl[] = {
		{CKA_EC_PARAMS, NULL_PTR, 0 },
		{CKA_EC_POINT, NULL_PTR, 0 }
	};
	ASN1_OBJECT *curve_oid_asn1 = NULL;
	EC_GROUP *ec_group = NULL;
	ASN1_OCTET_STRING *point_os = NULL;
	EC_POINT *ec_point = NULL;
	BIGNUM *pub_x_tmp = NULL;
	BIGNUM *pub_y_tmp = NULL;

	rv = method->C_GetAttributeValue(session_handle, key_handle, pub_tmpl, SIZEOF_ARRAY(pub_tmpl));
	if (rv != CKR_OK)
		goto err0;

	pub_tmpl[0].pValue = (CK_BYTE_PTR) OPENSSL_malloc(pub_tmpl[0].ulValueLen);
	pub_tmpl[1].pValue = (CK_BYTE_PTR) OPENSSL_malloc(pub_tmpl[1].ulValueLen);

	if (!pub_tmpl[0].pValue || !pub_tmpl[1].pValue) {
		rv = MEMORY_ALLOCATION_ERROR;
		goto err0;
	}

	rv = method->C_GetAttributeValue(session_handle, key_handle, pub_tmpl, SIZEOF_ARRAY(pub_tmpl));
	if (rv != CKR_OK)
		goto err0;
	
	const unsigned char *p = (const unsigned char *) pub_tmpl[0].pValue;
	curve_oid_asn1 = d2i_ASN1_OBJECT(NULL, &p, pub_tmpl[0].ulValueLen);
	if (!curve_oid_asn1) {
		rv = DER_DECODING_ERROR;
		goto err0;
	}

	int curve_nid = OBJ_obj2nid(curve_oid_asn1);
	if (curve_nid == NID_undef) {
		rv = UNKNOWN_CURVE_NAME;
		goto err0;
	}
	
	ec_group = EC_GROUP_new_by_curve_name(curve_nid);
	if (!ec_group) {
		rv = UNKNOWN_CURVE_NAME;
		goto err0;
	}

	p = pub_tmpl[1].pValue;
	point_os = d2i_ASN1_OCTET_STRING(NULL, &p, pub_tmpl[1].ulValueLen);
	if (!point_os) {
		rv = DER_DECODING_ERROR;
		goto err0;
	}
	const unsigned char *point_data = ASN1_STRING_get0_data(point_os);
	int point_data_len = ASN1_STRING_length(point_os);

	ec_point = EC_POINT_new(ec_group);
	if (!point_os) {
		rv = MEMORY_ALLOCATION_ERROR;
		goto err0;
	}

	if (!EC_POINT_oct2point(ec_group, ec_point, point_data, point_data_len, NULL)) {
		rv = GET_EC_POINT_ERROR;
		goto err0;
	}

	pub_x_tmp = BN_new();
	pub_y_tmp = BN_new();

	if (!pub_x_tmp || ! pub_y_tmp) {
		rv = MEMORY_ALLOCATION_ERROR;
		goto err0;
	}

	if(!EC_POINT_get_affine_coordinates(ec_group, ec_point, pub_x_tmp, pub_y_tmp, NULL)) {
		rv = GET_EC_POINT_ERROR;
		goto err0;
	}

	*pub_x = pub_x_tmp;
	*pub_y = pub_y_tmp;

	OPENSSL_free(pub_tmpl[0].pValue); 
	OPENSSL_free(pub_tmpl[1].pValue);
	ASN1_OBJECT_free(curve_oid_asn1);
	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_point);
	ASN1_STRING_free(point_os);

	return 0;

err0:
	OPENSSL_free(pub_tmpl[0].pValue); 
	OPENSSL_free(pub_tmpl[1].pValue);
	ASN1_OBJECT_free(curve_oid_asn1);
	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_point);
	ASN1_STRING_free(point_os);
	BN_free(pub_x_tmp);
	BN_free(pub_y_tmp);

	return rv;
}

int PKCS11_HELPER_get_private_ec_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **priv)
{
	int rv;

	CK_ATTRIBUTE priv_tmpl[] = {
		{CKA_VALUE, NULL_PTR, 0}
	};

	int priv_tmpl_len =  SIZEOF_ARRAY(priv_tmpl);

	rv = method->C_GetAttributeValue(session_handle, key_handle, priv_tmpl, priv_tmpl_len);
	if (rv != CKR_OK)
		goto err2;

	priv_tmpl[0].pValue = (CK_BYTE_PTR) OPENSSL_malloc(priv_tmpl[0].ulValueLen);

	rv = method->C_GetAttributeValue(session_handle, key_handle, priv_tmpl, priv_tmpl_len);
	if (rv != CKR_OK) {
		free(priv_tmpl[1].pValue);
		goto err1;
	}

	*priv = BN_bin2bn(priv_tmpl[0].pValue, priv_tmpl[0].ulValueLen, NULL);

	free(priv_tmpl[0].pValue);

	if (!*priv) {
		rv = GET_EC_PRIV_VALUE_ERROR;
		goto err0;
	}

	free_attributes_data(priv_tmpl, priv_tmpl_len);

	return 0;

err0:
	BN_free(*priv); *priv = NULL;
err1:
	free_attributes_data(priv_tmpl, priv_tmpl_len);
	free(priv_tmpl[0].pValue); 
	free(priv_tmpl[1].pValue);
err2:
	return rv;
}

int PKCS11_HELPER_get_public_rsa_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **n, BIGNUM **e)
{
	int rv;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
	};

	int tmpl_len = SIZEOF_ARRAY(tmpl);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl, tmpl_len);
	if (rv != CKR_OK)
		goto err0;

	int i;
	for (i = 0; i < tmpl_len; i++)
		tmpl[i].pValue = (CK_BYTE_PTR) OPENSSL_malloc(tmpl[i].ulValueLen);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl, tmpl_len);
	if (rv != CKR_OK)
		goto err0;
	
	*n = BN_bin2bn(tmpl[0].pValue, tmpl[0].ulValueLen, NULL);
	*e = BN_bin2bn(tmpl[1].pValue, tmpl[1].ulValueLen, NULL);

	free_attributes_data(tmpl, tmpl_len);

	return 0;

err0:
	free_attributes_data(tmpl, tmpl_len);
	return rv;
}

int PKCS11_HELPER_get_ec_curve_name(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, const char **curve_name)
{
	int rv;

	CK_ATTRIBUTE pub_tmpl[] = {
		{CKA_EC_PARAMS, NULL_PTR, 0},
	};

	rv = method->C_GetAttributeValue(session_handle, key_handle, pub_tmpl, SIZEOF_ARRAY(pub_tmpl));
	if (rv != CKR_OK)
		goto err2;

	pub_tmpl[0].pValue = (CK_BYTE_PTR) OPENSSL_malloc(pub_tmpl[0].ulValueLen);
	if (!pub_tmpl[0].pValue) {
		rv = MEMORY_ALLOCATION_ERROR;
		goto err2;
	}

	rv = method->C_GetAttributeValue(session_handle, key_handle, pub_tmpl, SIZEOF_ARRAY(pub_tmpl));
	if (rv != CKR_OK)
		goto err1;
	
	const unsigned char *p = pub_tmpl[0].pValue;
	EVP_PKEY *ec_key = d2i_KeyParams(EVP_PKEY_EC, NULL, &p, pub_tmpl[0].ulValueLen);
	if (!ec_key) {
		rv = DER_DECODING_ERROR;
		goto err1;
	}

	char curve_buf[128];
	if (!EVP_PKEY_get_utf8_string_param(ec_key, OSSL_PKEY_PARAM_GROUP_NAME, curve_buf, sizeof(curve_buf), NULL)) {
		rv = EC_CURVE_PARSING_ERROR;
		goto err0;
	}

	int curve_nid = OBJ_txt2nid(curve_buf);
	if (curve_nid == NID_undef) {
		rv = EC_CURVE_PARSING_ERROR;
		goto err0;
	}

	*curve_name = OBJ_nid2sn(curve_nid);
	
	EVP_PKEY_free(ec_key);
	OPENSSL_free(pub_tmpl[0].pValue);

	return 0;

err0:
	EVP_PKEY_free(ec_key);
err1:
	OPENSSL_free(pub_tmpl[0].pValue); 
err2:
	return rv;
}

int PKCS11_HELPER_get_private_rsa_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **d, BIGNUM **p, BIGNUM **q, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
	int rv;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0},
	};

	int tmpl_len = SIZEOF_ARRAY(tmpl);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl, tmpl_len);
	if (rv != CKR_OK)
		goto err0;

	int i;
	for (i = 0; i < tmpl_len; i++)
		tmpl[i].pValue = (CK_BYTE_PTR) OPENSSL_malloc(tmpl[i].ulValueLen);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl, tmpl_len);
	if (rv != CKR_OK)
		goto err0;
	

	if (d) *d = BN_bin2bn(tmpl[2].pValue, tmpl[2].ulValueLen, NULL);
	if (p) *p = BN_bin2bn(tmpl[3].pValue, tmpl[3].ulValueLen, NULL);
	if (q) *q = BN_bin2bn(tmpl[4].pValue, tmpl[4].ulValueLen, NULL);
	if (dmp1) *dmp1 = BN_bin2bn(tmpl[5].pValue, tmpl[5].ulValueLen, NULL);
	if (dmq1) *dmq1 = BN_bin2bn(tmpl[6].pValue, tmpl[6].ulValueLen, NULL);
	if (iqmp) *iqmp = BN_bin2bn(tmpl[7].pValue, tmpl[7].ulValueLen, NULL);

	free_attributes_data(tmpl, tmpl_len);

	return 0;

err0:
	free_attributes_data(tmpl, tmpl_len);
	return rv;
}

int PKCS11_HELPER_get_key_type(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, CK_KEY_TYPE *type)
{
	int rv;
	CK_KEY_TYPE key_type_attr = 0;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_KEY_TYPE, &key_type_attr, sizeof(CK_KEY_TYPE)},
	};

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl, SIZEOF_ARRAY(tmpl));
	if (rv != CKR_OK)
		return rv;
	
	*type = key_type_attr;

	return 0;
}

int PKCS11_HELPER_get_sensitive_attribute(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE obj_handle, CK_BBOOL *sensitive)
{
	if (!sensitive)
		return 0;
	
	int rv;
	CK_BBOOL sensitive_attr = 0;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_SENSITIVE, &sensitive_attr, sizeof(CK_BBOOL)},
	};

	rv = method->C_GetAttributeValue(session_handle, obj_handle, tmpl, SIZEOF_ARRAY(tmpl));
	if (rv != CKR_OK)
		return rv;
	
	*sensitive = sensitive_attr;

	return 0;
}

int PKCS11_HELPER_get_obj_metadata(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE obj_handle, char **label, unsigned char **id, size_t *id_len)
{
	int rv;

	CK_ATTRIBUTE tmpl[] = {
		{CKA_LABEL, NULL_PTR, 0},
		{CKA_ID, NULL_PTR, 0},
	};

	rv = method->C_GetAttributeValue(session_handle, obj_handle, tmpl, SIZEOF_ARRAY(tmpl));
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
		goto err;
	
	if ((label && (tmpl[0].ulValueLen == CK_UNAVAILABLE_INFORMATION || tmpl[0].ulValueLen == 0)) ||
		(id && (tmpl[1].ulValueLen == CK_UNAVAILABLE_INFORMATION || tmpl[1].ulValueLen == 0))) {
		rv = UNAVAILABLE_ATTRIBUTE_ERROR;
		goto err;
	}
	
	if (label)
		tmpl[0].pValue = OPENSSL_malloc(tmpl[0].ulValueLen + 1);
	if (id)
		tmpl[1].pValue = OPENSSL_malloc(tmpl[1].ulValueLen);

	if ((label && !tmpl[0].pValue) || (id && !tmpl[1].pValue)) {
		rv = MEMORY_ALLOCATION_ERROR;
		goto err;
	}
	
	if ((rv = method->C_GetAttributeValue(session_handle, obj_handle, tmpl, SIZEOF_ARRAY(tmpl))) != CKR_OK) {
		goto err;
	}

	if (label) {
		char *lbl_str = (char *) tmpl[0].pValue;
		lbl_str[tmpl[0].ulValueLen] = '\0';
		*label = lbl_str;
	}

	if (id) {
		*id = (unsigned char *) tmpl[1].pValue;
		*id_len = tmpl[1].ulValueLen;
	}
	
	return 0;

err:

	OPENSSL_free(tmpl[0].pValue);
	OPENSSL_free(tmpl[1].pValue);

	return rv;
}

int PKCS11_HELPER_find_public_from_private(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, CK_OBJECT_HANDLE *pub_key_handle)
{
	CK_RV rv;
    CK_ULONG keyCount = 0;
	CK_ATTRIBUTE tmpl_id[] = {
		{CKA_ID, NULL_PTR, 0 },
	};
	int i;
	int tmpl_id_size = SIZEOF_ARRAY(tmpl_id);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl_id, tmpl_id_size);
	if (rv != CKR_OK)
		goto err1;
	
	for(i = 0; i < tmpl_id_size; i++)
		tmpl_id[i].pValue = malloc(tmpl_id[i].ulValueLen);

	rv = method->C_GetAttributeValue(session_handle, key_handle, tmpl_id, tmpl_id_size);
	if (rv != CKR_OK){
		goto err0;
	}

	CK_OBJECT_CLASS public_key  = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE public_tmpl[] = {
			{CKA_ID, tmpl_id[0].pValue, tmpl_id[0].ulValueLen },
			{CKA_CLASS, &public_key, sizeof(public_key) }
	};

	rv = method->C_FindObjectsInit(session_handle, public_tmpl, SIZEOF_ARRAY(public_tmpl));
	if (rv != CKR_OK)
		goto err0;
	

	rv = method->C_FindObjects(session_handle, pub_key_handle, 1, &keyCount);
	if (rv != CKR_OK)
		goto err0;

	if (!keyCount) {
		rv = CKR_OBJECT_HANDLE_INVALID;
		goto err0;
	}

err0:
	for(i = 0; i < tmpl_id_size; i++)
		free(tmpl_id[i].pValue);
err1:
	return rv;
}

CK_RV PKCS11_HELPER_create_mutex(void **mutex)
{
	pthread_mutex_t *my_mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if (pthread_mutex_init(my_mutex, NULL)){
		return CKR_MUTEX_BAD;
	}
	*mutex = my_mutex;
	return CKR_OK;
}
CK_RV PKCS11_HELPER_destroy_mutex(void *mutex)
{
	pthread_mutex_t *my_mutex = (pthread_mutex_t *)mutex;
	if (pthread_mutex_destroy(my_mutex)){
		return CKR_MUTEX_BAD;
	}
	free(my_mutex);
	return CKR_OK;
}
CK_RV PKCS11_HELPER_lock_mutex(void *mutex)
{
	if (pthread_mutex_lock((pthread_mutex_t *)mutex)){
		return CKR_MUTEX_BAD;
	}
	return CKR_OK;
}
CK_RV PKCS11_HELPER_unlock_mutex(void *mutex)
{
	if (pthread_mutex_unlock((pthread_mutex_t *)mutex)){
		return CKR_MUTEX_BAD;
	}
	return CKR_OK;
}

void PKCS11_HELPER_set_all_mutex(CK_C_INITIALIZE_ARGS_PTR args)
{
	args->CreateMutex = PKCS11_HELPER_create_mutex;
	args->DestroyMutex = PKCS11_HELPER_destroy_mutex;
	args->LockMutex = PKCS11_HELPER_lock_mutex;
	args->UnlockMutex = PKCS11_HELPER_unlock_mutex;
}

int PKCS11_HELPER_find_token(CK_FUNCTION_LIST_PTR method, const char *tokenLabel, CK_SLOT_ID_PTR slotFound) {
	CK_ULONG pulCount = 0;
	CK_RV rv;
	CK_SLOT_ID_PTR slotPtr = NULL;
	CK_TOKEN_INFO tokenInfo;
	int found = FALSE;
	int i = 0;

	rv = method->C_GetSlotList(CK_TRUE, NULL, &pulCount);
	if (rv != CKR_OK){
		goto err0;
	}

	slotPtr = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * pulCount);
	rv = method->C_GetSlotList(CK_TRUE, slotPtr, &pulCount);
	if (rv != CKR_OK){
		goto err1;
	}

	for (; i < pulCount; ++i){
		rv = method->C_GetTokenInfo(slotPtr[i], &tokenInfo);
		if (rv != CKR_OK){
			goto err1;
		}
		if (memcmp(tokenInfo.label, tokenLabel, 32) == 0){
			*slotFound = slotPtr[i];
			found = TRUE;
			break;
		}
	}
	if (!found){
		return 1;
	}

	free(slotPtr);
	return 0;

err1:
	free(slotPtr);
err0:
	return rv;
}

/**
 * @brief Expected format for key_info is [slot_label]:[pin]:[key_label]
 */
int PKCS11_HELPER_parse_priv_key_info(CK_FUNCTION_LIST_PTR method, const char *key_info, CK_SLOT_ID* slot_id,
	char **pin, char **key_label)
{
	const char *next_substr;
	const char *remaining_string = key_info;

	next_substr = strchr(remaining_string, ':');
	if (!next_substr)
		return PARSE_PRIV_KEY_INFO_ERROR;
	int slot_str_len = next_substr - remaining_string;
	char slot_str[slot_str_len * sizeof(char) + 1];
	memcpy(slot_str, remaining_string, slot_str_len);
	slot_str[slot_str_len] = '\0';

	remaining_string = next_substr + 1;
	next_substr = strchr(remaining_string, ':');
	if (!next_substr)
		return PARSE_PRIV_KEY_INFO_ERROR;
	int pin_len = next_substr - remaining_string;
	*pin = (char *) OPENSSL_malloc((pin_len) * sizeof(char) + 1);
	memcpy(*pin, remaining_string, pin_len);
	(*pin)[pin_len] = '\0';

	remaining_string = next_substr + 1;
	*key_label = (char *) OPENSSL_malloc(strlen(remaining_string) * sizeof(char) + 1);
	strcpy(*key_label, remaining_string);

	PKCS11_HELPER_slot_label_to_id(method, slot_str, slot_id);

	return 0;
}

int PKCS11_HELPER_parse_uri_args(CK_FUNCTION_LIST_PTR method, const char *uri, CK_SLOT_ID *slot_id, char **pin,
	char **obj_label)
{
	const char *next_substr;
	const char *remaining_string;

	const char *pkcs11_tag = "pkcs11";
	const char *slot_label_attr = "slot-id";
	const char *pin_value_attr = "pin-value";
	const char *object_attr = "object";

	unsigned int pkcs11_tag_len = strlen(pkcs11_tag);
	unsigned int slot_label_attr_len = strlen(slot_label_attr);
	unsigned int pin_value_attr_len = strlen(pin_value_attr);	
	unsigned int object_attr_len = strlen(object_attr);

	const char *next_attr_separator = NULL;
	const char *name_value_separator = NULL;
	const char *name_start = NULL;
	const char *value_start = NULL;
	int name_len;
	int value_len;

	remaining_string = strchr(uri, ':');
	
	if (remaining_string == NULL)
		return PARSE_URI_ERROR;
	
	if (remaining_string - uri != pkcs11_tag_len || memcmp(pkcs11_tag, uri, pkcs11_tag_len) != 0)
		return PARSE_URI_ERROR;
	
	do {
		remaining_string = remaining_string + 1;
		if (strlen(remaining_string) == 0)
			return PARSE_URI_ERROR;
		
		next_attr_separator = strchr(remaining_string, ';');
		
		name_value_separator = strchr(remaining_string, '=');
		if (name_value_separator == NULL)
			return PARSE_URI_ERROR;

		name_start = remaining_string;
		value_start = name_value_separator + 1;
		
		name_len = name_value_separator - remaining_string;
		
		if (next_attr_separator != NULL) {
            value_len = next_attr_separator - value_start;
        } else {
            value_len = strlen(value_start);
        }
		
		if (name_len == 0 || value_len == 0)
			return PARSE_URI_ERROR;
		
		if (name_len == slot_label_attr_len && memcmp(name_start, slot_label_attr, slot_label_attr_len) == 0) {
			char *slot_label = OPENSSL_malloc(value_len + 1);
			if (!slot_label)
				return MEMORY_ALLOCATION_ERROR;

			memcpy(slot_label, value_start, value_len);
			slot_label[value_len] = '\0';
			PKCS11_HELPER_slot_label_to_id(method, slot_label, slot_id);
			OPENSSL_free(slot_label);
		} else if (name_len == pin_value_attr_len && memcmp(name_start, pin_value_attr, pin_value_attr_len) == 0) {
			*pin = OPENSSL_malloc(value_len + 1);
			if (!pin)
				return MEMORY_ALLOCATION_ERROR;

			memcpy(*pin, value_start, value_len);
			(*pin)[value_len] = '\0';
		} else if (name_len == object_attr_len && memcmp(name_start, object_attr, object_attr_len) == 0) {
			*obj_label = OPENSSL_malloc(value_len + 1);
			if (!obj_label)
				return MEMORY_ALLOCATION_ERROR;

			memcpy(*obj_label, value_start, value_len);
			*(obj_label)[value_len] = '\0';
		}

		remaining_string = strchr(remaining_string, ';');
	} while (remaining_string != NULL);

	return 0;
}

int PKCS11_HELPER_slot_label_to_id(CK_FUNCTION_LIST_PTR method, const char *slot_label, CK_SLOT_ID *slot_id)
{
	if (!is_valid_int(slot_label)) {
		// proprably the slot is a label, not an ID.
		// find the appropriate ID
		char slot_padded[33];
		sprintf(slot_padded, "%-32s", slot_label);

		int rv;
		if((rv =PKCS11_HELPER_find_token(method, slot_padded, slot_id)) != 0) {
			return rv;
		}
	} else {
		*slot_id = (CK_SLOT_ID) atoi(slot_label);
	}
	return 0;
}

int is_valid_int(const char *str)
{
   // Handle negative numbers.
   //
   if (*str == '-')
      ++str;

   // Handle empty string or just "-".
   //
   if (!*str)
      return FALSE;

   // Check for non-digit chars in the rest of the stirng.
   //
   while (*str)
   {
      if (!isdigit(*str))
         return FALSE;
      else
         ++str;
   }

   return TRUE;
}

const char *curveNid2Name(int curve_nid)
{
	size_t i;
    for (i = 0; i < SIZEOF_ARRAY(curve_list); i++) {
        if (curve_list[i].nid == curve_nid)
        	return curve_list[i].name;
    }

	for (i = 0; i < SIZEOF_ARRAY(nist_curves); i++) {
        if (nist_curves[i].nid == curve_nid)
        	return nist_curves[i].name;
	}

	return NULL;
}

int curveName2nid(const char* name)
{
	size_t i;
    for (i = 0; i < SIZEOF_ARRAY(curve_list); i++) {
        if (strcmp(curve_list[i].name, name) == 0)
        	return curve_list[i].nid;
    }

	for (i = 0; i < SIZEOF_ARRAY(nist_curves); i++) {
		if (strcmp(nist_curves[i].name, name) == 0)
			return nist_curves[i].nid;
	}

	return NID_undef;
}

int curveName2P11Curve(const char* name, CK_BYTE **curveParam)
{
	int nid = curveName2nid(name);

	if (nid == NID_undef)
		return 0;

	ASN1_OBJECT *obj = OBJ_nid2obj(nid);

	if (!obj)
		return 0;
	
	unsigned char *der = NULL;
	int curveSize = i2d_ASN1_OBJECT(obj, &der);

	ASN1_OBJECT_free(obj);

	if (curveSize <= 0)
		return 0;
	
	*curveParam = der;

	return curveSize;
}

int calculate_sha1_digest(const unsigned char *data, size_t data_len, 
    unsigned char *out_hash, unsigned int *out_hash_len) 
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_MD *md = NULL;
    int ret = 0;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        goto cleanup;

    md = EVP_MD_fetch(NULL, "SHA1", NULL);
    if (!md)
        goto cleanup;

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
        goto cleanup;

    if (EVP_DigestUpdate(mdctx, data, data_len) != 1)
        goto cleanup;

    if (EVP_DigestFinal_ex(mdctx, out_hash, out_hash_len) != 1)
        goto cleanup;

    ret = 1;

cleanup:
	EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    
    return ret;
}

int calculate_rsa_public_parameters(BN_CTX *ctx, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, BIGNUM **n,
	BIGNUM **e)
{
	BN_CTX_start(ctx);

	BIGNUM *p_minus_1 = BN_CTX_get(ctx);
	BIGNUM *q_minus_1 = BN_CTX_get(ctx);

	int ret = 0;
	
	if (!p_minus_1 || !q_minus_1) {
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}
	
	BN_sub(p_minus_1, p, BN_value_one());
	BN_sub(q_minus_1, q, BN_value_one());

	BIGNUM *n_tmp = BN_CTX_get(ctx);
	BIGNUM *e_tmp = BN_CTX_get(ctx);
	BIGNUM *phi = BN_CTX_get(ctx);

	if (!n_tmp || !e_tmp || !phi) {
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}

	if (!BN_mul(n_tmp, p, q, ctx)) {
		ret = RSA_PUBLIC_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}

	if (!BN_mul(phi, p_minus_1, q_minus_1, ctx)) {
		ret = RSA_PUBLIC_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}

	if (!BN_mod_inverse(e_tmp, d, phi, ctx)) {
		ret = RSA_PUBLIC_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}

	*n = BN_dup(n_tmp);
	*e = BN_dup(e_tmp);

	if (!*n || !*e) {
		BN_free(*n); *n = NULL;
		BN_free(*e); *e = NULL;
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}

cleanup:
	BN_CTX_end(ctx);

	return ret;
}

int calculate_rsa_crt_parameters(BN_CTX *ctx, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, BIGNUM **dmp1,
	BIGNUM **dmq1, BIGNUM **iqmp)
{
	BN_CTX_start(ctx);

	BIGNUM *p_minus_1 = BN_CTX_get(ctx);
	BIGNUM *q_minus_1 = BN_CTX_get(ctx);

	int ret = 0;
	
	if (!p_minus_1 || !q_minus_1) {
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}
	
	BN_sub(p_minus_1, p, BN_value_one());
	BN_sub(q_minus_1, q, BN_value_one());

	BIGNUM *dmp1_tmp = BN_CTX_get(ctx);
	BIGNUM *dmq1_tmp = BN_CTX_get(ctx);
	BIGNUM *iqmp_tmp = BN_CTX_get(ctx);

	if (!dmp1_tmp || !dmq1_tmp || !iqmp_tmp) {
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}
	
	if (!BN_mod(dmp1_tmp, d, p_minus_1, ctx)) {
		ret = RSA_CRT_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}
	
	if (!BN_mod(dmq1_tmp, d, q_minus_1, ctx)) {
		ret = RSA_CRT_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}
	
	if (!BN_mod_inverse(iqmp_tmp, q, p, ctx)) {
		ret = RSA_CRT_PARAMETERS_CALCULATION_ERROR;
		goto cleanup;
	}

	*dmp1 = BN_dup(dmp1_tmp);
	*dmq1 = BN_dup(dmq1_tmp);
	*iqmp = BN_dup(iqmp_tmp);

	if (!*dmp1 || !*dmq1 || !*iqmp) {
		BN_free(*dmp1); *dmp1 = NULL;
		BN_free(*dmq1); *dmq1 = NULL;
		BN_free(*iqmp); *iqmp = NULL;
		ret = MEMORY_ALLOCATION_ERROR;
		goto cleanup;
	}

cleanup:
	BN_CTX_end(ctx);

	return ret;
}

int make_rsa_digest_info(unsigned char *md_value, unsigned int md_len, unsigned int md_nid, unsigned char **digest_info,
	size_t *digest_info_len)
{
	int ret;
	
	X509_SIG *digest_info_obj = NULL;
	unsigned char *digest_info_der = NULL;

	digest_info_obj = X509_SIG_new();
	if (!digest_info_obj) {
		ret = MEMORY_ALLOCATION_ERROR;
		goto err;
	}

	X509_ALGOR *palg;
	ASN1_OCTET_STRING *pdigest;
	X509_SIG_getm(digest_info_obj, &palg, &pdigest);

	palg->algorithm = OBJ_nid2obj(md_nid);
	palg->parameter = ASN1_TYPE_new();
	palg->parameter->type = V_ASN1_NULL;

	ASN1_STRING_set(pdigest, md_value, md_len);

	int digest_info_der_len;

	if ((digest_info_der_len = i2d_X509_SIG(digest_info_obj, &digest_info_der)) <= 0) {
		ret = DER_ENCODING_ERROR;
		goto err;
	}

	X509_SIG_free(digest_info_obj);
	
	*digest_info = digest_info_der;
	*digest_info_len = digest_info_der_len;

	return 0;

err:
	OPENSSL_free(digest_info_der);
	X509_SIG_free(digest_info_obj);
	return ret;
}