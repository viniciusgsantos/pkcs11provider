#ifndef PKCS11_STORE_H_
#define PKCS11_STORE_H_

#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/pkcs11_types.h"

#include <openssl/core_dispatch.h>

struct pkcs11_key_reference_st {
    struct pkcs11_prov_ctx_st *provctx;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE priv_key_handle;
	CK_OBJECT_HANDLE pub_key_handle;
	int has_priv_key_handle;
	int has_pub_key_handle;
    // TODO add magic number
};

struct pkcs11_storemgmt_buffer_entry_st {
	CK_OBJECT_HANDLE handle;
	CK_BYTE *id;
	size_t id_len;
	CK_OBJECT_CLASS class;
	CK_UTF8CHAR *label;
	int read;
};

struct pkcs11_storemgmt_loader_ctx_st {
	struct pkcs11_prov_ctx_st *provctx;
	CK_SESSION_HANDLE session_handle;
	CK_SLOT_ID slot_id;
	struct pkcs11_storemgmt_buffer_entry_st *buffer;
	size_t buffer_len;
	int next_obj;
	char *pin;
	char *alias;
	int initialized;
	int eof;
};

typedef struct pkcs11_key_reference_st PKCS11_KEY_REFERENCE;
typedef struct pkcs11_storemgmt_loader_ctx_st PKCS11_STOREMGMT_LOADER_CTX;
typedef struct pkcs11_storemgmt_buffer_entry_st PKCS11_STOREMGMT_BUFFER_ENTRY;

static OSSL_FUNC_store_open_fn pkcs11_store_open;
static OSSL_FUNC_store_settable_ctx_params_fn pkcs11_store_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn pkcs11_store_set_ctx_params;
static OSSL_FUNC_store_load_fn pkcs11_store_load;
static OSSL_FUNC_store_eof_fn pkcs11_store_eof;
static OSSL_FUNC_store_close_fn pkcs11_store_close;
static OSSL_FUNC_store_export_object_fn pkcs11_store_export_obj;

const extern OSSL_DISPATCH pkcs11_store_fns[8];

#endif