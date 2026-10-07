#ifndef PKCS11_HELPER_H_
#define PKCS11_HELPER_H_

#include "pkcs11provider/pkcs11/pkcs11.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <string.h>
#include <pthread.h>

#define SIZEOF_ARRAY(x) (sizeof(x)/sizeof(x[0]))

typedef struct ec_name2nid_st {
    const char *name;
    int nid;
} EC_NAME2NID;

static const EC_NAME2NID curve_list[] = {
    /* prime field curves */
    /* secg curves */
    {"secp112r1", NID_secp112r1 },
    {"secp112r2", NID_secp112r2 },
    {"secp128r1", NID_secp128r1 },
    {"secp128r2", NID_secp128r2 },
    {"secp160k1", NID_secp160k1 },
    {"secp160r1", NID_secp160r1 },
    {"secp160r2", NID_secp160r2 },
    {"secp192k1", NID_secp192k1 },
    {"secp224k1", NID_secp224k1 },
    {"secp224r1", NID_secp224r1 },
    {"secp256k1", NID_secp256k1 },
    {"secp384r1", NID_secp384r1 },
    {"secp521r1", NID_secp521r1 },
    /* X9.62 curves */
    {"prime192v1", NID_X9_62_prime192v1 },
    {"prime192v2", NID_X9_62_prime192v2 },
    {"prime192v3", NID_X9_62_prime192v3 },
    {"prime239v1", NID_X9_62_prime239v1 },
    {"prime239v2", NID_X9_62_prime239v2 },
    {"prime239v3", NID_X9_62_prime239v3 },
    {"prime256v1", NID_X9_62_prime256v1 },
    /* characteristic two field curves */
    /* NIST/SECG curves */
    {"sect113r1", NID_sect113r1 },
    {"sect113r2", NID_sect113r2 },
    {"sect131r1", NID_sect131r1 },
    {"sect131r2", NID_sect131r2 },
    {"sect163k1", NID_sect163k1 },
    {"sect163r1", NID_sect163r1 },
    {"sect163r2", NID_sect163r2 },
    {"sect193r1", NID_sect193r1 },
    {"sect193r2", NID_sect193r2 },
    {"sect233k1", NID_sect233k1 },
    {"sect233r1", NID_sect233r1 },
    {"sect239k1", NID_sect239k1 },
    {"sect283k1", NID_sect283k1 },
    {"sect283r1", NID_sect283r1 },
    {"sect409k1", NID_sect409k1 },
    {"sect409r1", NID_sect409r1 },
    {"sect571k1", NID_sect571k1 },
    {"sect571r1", NID_sect571r1 },
    /* X9.62 curves */
    {"c2pnb163v1", NID_X9_62_c2pnb163v1 },
    {"c2pnb163v2", NID_X9_62_c2pnb163v2 },
    {"c2pnb163v3", NID_X9_62_c2pnb163v3 },
    {"c2pnb176v1", NID_X9_62_c2pnb176v1 },
    {"c2tnb191v1", NID_X9_62_c2tnb191v1 },
    {"c2tnb191v2", NID_X9_62_c2tnb191v2 },
    {"c2tnb191v3", NID_X9_62_c2tnb191v3 },
    {"c2pnb208w1", NID_X9_62_c2pnb208w1 },
    {"c2tnb239v1", NID_X9_62_c2tnb239v1 },
    {"c2tnb239v2", NID_X9_62_c2tnb239v2 },
    {"c2tnb239v3", NID_X9_62_c2tnb239v3 },
    {"c2pnb272w1", NID_X9_62_c2pnb272w1 },
    {"c2pnb304w1", NID_X9_62_c2pnb304w1 },
    {"c2tnb359v1", NID_X9_62_c2tnb359v1 },
    {"c2pnb368w1", NID_X9_62_c2pnb368w1 },
    {"c2tnb431r1", NID_X9_62_c2tnb431r1 },
    /*
     * the WAP/WTLS curves [unlike SECG, spec has its own OIDs for curves
     * from X9.62]
     */
    {"wap-wsg-idm-ecid-wtls1", NID_wap_wsg_idm_ecid_wtls1 },
    {"wap-wsg-idm-ecid-wtls3", NID_wap_wsg_idm_ecid_wtls3 },
    {"wap-wsg-idm-ecid-wtls4", NID_wap_wsg_idm_ecid_wtls4 },
    {"wap-wsg-idm-ecid-wtls5", NID_wap_wsg_idm_ecid_wtls5 },
    {"wap-wsg-idm-ecid-wtls6", NID_wap_wsg_idm_ecid_wtls6 },
    {"wap-wsg-idm-ecid-wtls7", NID_wap_wsg_idm_ecid_wtls7 },
    {"wap-wsg-idm-ecid-wtls8", NID_wap_wsg_idm_ecid_wtls8 },
    {"wap-wsg-idm-ecid-wtls9", NID_wap_wsg_idm_ecid_wtls9 },
    {"wap-wsg-idm-ecid-wtls10", NID_wap_wsg_idm_ecid_wtls10 },
    {"wap-wsg-idm-ecid-wtls11", NID_wap_wsg_idm_ecid_wtls11 },
    {"wap-wsg-idm-ecid-wtls12", NID_wap_wsg_idm_ecid_wtls12 },
    /* IPSec curves */
    {"Oakley-EC2N-3", NID_ipsec3 },
    {"Oakley-EC2N-4", NID_ipsec4 },
    /* brainpool curves */
    {"brainpoolP160r1", NID_brainpoolP160r1 },
    {"brainpoolP160t1", NID_brainpoolP160t1 },
    {"brainpoolP192r1", NID_brainpoolP192r1 },
    {"brainpoolP192t1", NID_brainpoolP192t1 },
    {"brainpoolP224r1", NID_brainpoolP224r1 },
    {"brainpoolP224t1", NID_brainpoolP224t1 },
    {"brainpoolP256r1", NID_brainpoolP256r1 },
    {"brainpoolP256t1", NID_brainpoolP256t1 },
    {"brainpoolP320r1", NID_brainpoolP320r1 },
    {"brainpoolP320t1", NID_brainpoolP320t1 },
    {"brainpoolP384r1", NID_brainpoolP384r1 },
    {"brainpoolP384t1", NID_brainpoolP384t1 },
    {"brainpoolP512r1", NID_brainpoolP512r1 },
    {"brainpoolP512t1", NID_brainpoolP512t1 },
    /* SM2 curve */
    {"SM2", NID_sm2 },
};

static const EC_NAME2NID nist_curves[] = {
    {"B-163", NID_sect163r2},
    {"B-233", NID_sect233r1},
    {"B-283", NID_sect283r1},
    {"B-409", NID_sect409r1},
    {"B-571", NID_sect571r1},
    {"K-163", NID_sect163k1},
    {"K-233", NID_sect233k1},
    {"K-283", NID_sect283k1},
    {"K-409", NID_sect409k1},
    {"K-571", NID_sect571k1},
    {"P-192", NID_X9_62_prime192v1},
    {"P-224", NID_secp224r1},
    {"P-256", NID_X9_62_prime256v1},
    {"P-384", NID_secp384r1},
    {"P-521", NID_secp521r1}
};

int PKCS11_HELPER_initialize(CK_FUNCTION_LIST_PTR method, const char *init_args);

int PKCS11_HELPER_open_session(CK_FUNCTION_LIST_PTR method, const CK_SLOT_ID slot_id,
	CK_SESSION_HANDLE *session_handle);

int PKCS11_HELPER_login(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
							const char *user_pin);

int PKCS11_HELPER_logout(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle);

int PKCS11_HELPER_close_session(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle);

static int PKCS11_HELPER_get_key_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
    const char *key_label, int isPrivate, CK_OBJECT_HANDLE *object);

int PKCS11_HELPER_get_public_key_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
	const char *key_label, CK_OBJECT_HANDLE *object);

int PKCS11_HELPER_get_private_key_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
	const char *key_label, CK_OBJECT_HANDLE *object);

int PKCS11_HELPER_get_obj_handle(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle,
    const char *alias, CK_OBJECT_HANDLE *obj_handle, CK_OBJECT_CLASS *obj_class);

int PKCS11_HELPER_find_obj_by_label_init(CK_FUNCTION_LIST_PTR method,
										    const CK_SESSION_HANDLE session_handle,
    									    const char *label);

int PKCS11_HELPER_find_obj(CK_FUNCTION_LIST_PTR method,
							   const CK_SESSION_HANDLE session_handle,
							   CK_OBJECT_HANDLE *obj_handle,
							   CK_ULONG_PTR obj_count);

int PKCS11_HELPER_find_obj_final(CK_FUNCTION_LIST_PTR method, const CK_SESSION_HANDLE session_handle);

int PKCS11_HELPER_get_obj_class(CK_FUNCTION_LIST_PTR method,
                                    const CK_SESSION_HANDLE session_handle,
                                    const CK_OBJECT_HANDLE obj_handle,
                                    CK_OBJECT_CLASS *obj_class);

int PKCS11_HELPER_gen_keypair(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
	CK_MECHANISM *mechanism,
	CK_ATTRIBUTE_PTR pubKeyAttributes, unsigned long pubKeyAttributesLen,
	CK_ATTRIBUTE_PTR privKeyAttributes, unsigned long privKeyAttributesLen,
	CK_OBJECT_HANDLE *pub_key_handle, CK_OBJECT_HANDLE *priv_key_handle);

int PKCS11_HELPER_find_token(CK_FUNCTION_LIST_PTR method, const char *tokenLabel, CK_SLOT_ID_PTR slotFound);

int PKCS11_HELPER_parse_priv_key_info(CK_FUNCTION_LIST_PTR method, const char *key_info, CK_SLOT_ID *slot_id,
    char **pin, char **key_label);

int PKCS11_HELPER_parse_uri_args(CK_FUNCTION_LIST_PTR method, const char *uri, CK_SLOT_ID *slot_id, char **pin,
    char **obj_label);

int PKCS11_HELPER_slot_label_to_id(CK_FUNCTION_LIST_PTR method, const char *slot_label, CK_SLOT_ID *slot_id);

int PKCS11_HELPER_create_object(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_ATTRIBUTE *tmpl, CK_ULONG tmpl_size);

int PKCS11_HELPER_get_private_ec_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **priv);

int PKCS11_HELPER_get_public_ec_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **pub_x, BIGNUM **pub_y);

int PKCS11_HELPER_get_ec_curve_name(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, const char **curve_name);

int PKCS11_HELPER_get_private_rsa_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **d, BIGNUM **p, BIGNUM **q, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp);

int PKCS11_HELPER_get_public_rsa_attributes(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, BIGNUM **n, BIGNUM **e);

int PKCS11_HELPER_get_key_type(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, CK_KEY_TYPE *key_type);

int PKCS11_HELPER_get_sensitive_attribute(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE obj_handle, CK_BBOOL *sensitive);

int PKCS11_HELPER_get_obj_metadata(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE obj_handle, char **label, unsigned char **id, size_t *id_len);

int PKCS11_HELPER_find_public_from_private(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle, CK_OBJECT_HANDLE *pub_key_handle);

// Callback functions for locking Cryptoki
CK_RV PKCS11_HELPER_create_mutex(void **mutex);
CK_RV PKCS11_HELPER_destroy_mutex(void *mutex);
CK_RV PKCS11_HELPER_lock_mutex(void *mutex);
CK_RV PKCS11_HELPER_unlock_mutex(void *mutex);
void PKCS11_HELPER_set_all_mutex(CK_C_INITIALIZE_ARGS_PTR args);

// Util functions
int is_valid_int(const char *str);

const char *curveNid2Name(int curve_nid);

int curveName2nid(const char* name);

int curveName2P11Curve(const char* name, CK_BYTE **curveParam);

int calculate_sha1_digest(const unsigned char *data, size_t data_len, 
    unsigned char *out_hash, unsigned int *out_hash_len);

int calculate_rsa_public_parameters(BN_CTX *ctx, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, BIGNUM **n,
    BIGNUM **e);

int calculate_rsa_crt_parameters(BN_CTX *ctx, const BIGNUM *d, const BIGNUM *p, const BIGNUM *q, BIGNUM **dmp1,
    BIGNUM **dmq1, BIGNUM **iqmp);

int make_rsa_digest_info(unsigned char *md_value, unsigned int md_len, unsigned int md_nid, unsigned char **digest_info,
	size_t *digest_info_len);

#endif /* PKCS11_HELPER_H_ */
