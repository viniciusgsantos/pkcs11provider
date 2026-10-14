#include "pkcs11provider/pkcs11_store.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_types.h"
#include "pkcs11provider/pkcs11/pkcs11.h"
#include "pkcs11provider/session.h"

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>

static void *pkcs11_store_open(void *provctx, const char *uri)
{
	PKCS11_PROV_CTX *pctx = (PKCS11_PROV_CTX *) provctx;
	CK_FUNCTION_LIST_PTR method = pctx->method;
	PKCS11_STOREMGMT_LOADER_CTX *loaderctx = OPENSSL_zalloc(sizeof(PKCS11_STOREMGMT_LOADER_CTX));
	if (!loaderctx) {
		ERR_core_raise(pctx->core_handle, MEMORY_ALLOCATION_ERROR);
		goto err1;
	}
	loaderctx->provctx = provctx;
	loaderctx->eof = 0;

	int ret;
	if ((ret = PKCS11_HELPER_parse_uri_args(method, uri,
			&loaderctx->slot_id, &loaderctx->pin, &loaderctx->alias)) != 0) {
		ERR_core_raise(pctx->core_handle, ret);
		goto err1;
	}

	CK_SESSION_HANDLE session_handle;
	if ((ret = open_session(pctx, loaderctx->slot_id, &session_handle)) != 0) {
		ERR_core_raise(pctx->core_handle, ret);
		goto err1;
	}

	if((ret = user_login(pctx, loaderctx->pin)) != 0) {
		ERR_core_raise(pctx->core_handle, ret);
		goto err0;
	}
	
	loaderctx->session_handle = session_handle;

	return loaderctx;

err0:
	close_session(pctx, session_handle);
err1:
	OPENSSL_free(loaderctx);
	OPENSSL_clear_free(loaderctx->pin, strlen(loaderctx->pin) + 1); loaderctx->pin = NULL;
	ERR_core_raise(pctx->core_handle, ret);
	return NULL;

}

static const OSSL_PARAM *pkcs11_store_settable_ctx_params(void *provctx)
{
	OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
		OSSL_PARAM_END
	};
	return OSSL_PARAM_dup(params);
}

static int pkcs11_store_set_ctx_params(void *loaderctx, const OSSL_PARAM *params)
{
	PKCS11_STOREMGMT_LOADER_CTX *lctx = (PKCS11_STOREMGMT_LOADER_CTX *) loaderctx;
	if (params) {
		int i;
		for (i = 0; params[i].key != NULL; i++) {
			if (strcmp(params[i].key, OSSL_STORE_PARAM_ALIAS) == 0) {
				lctx->alias = OPENSSL_malloc(params[i].data_size + 1);
				OPENSSL_strlcpy(lctx->alias, params[i].data, params[i].data_size + 1);
			}
		}
	}
	return TRUE;
}

static int pkcs11_store_load(void *loaderctx, OSSL_CALLBACK *object_cb, void *object_cbarg,
	OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	PKCS11_STOREMGMT_LOADER_CTX *lctx = (PKCS11_STOREMGMT_LOADER_CTX *) loaderctx;
	PKCS11_PROV_CTX *provctx = lctx->provctx;
	CK_FUNCTION_LIST_PTR method = provctx->method;
	const OSSL_CORE_HANDLE *handle = lctx->provctx->core_handle;

	CK_OBJECT_HANDLE *obj_handles = NULL;
	
	int ret;

	if (!lctx->initialized) {
		if ((ret = PKCS11_HELPER_find_obj_by_label_init(method, lctx->session_handle, lctx->alias)) != 0) {
			ERR_core_raise(handle, ret);;
			goto errinit2;
		}
		
		CK_ULONG capacity = 64;
		CK_ULONG total_object_count = 0;
		
		obj_handles = OPENSSL_malloc(capacity * sizeof(CK_OBJECT_HANDLE));
		if (!obj_handles) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto errinit1;
		}

		do {
			CK_ULONG requested = capacity - total_object_count;
			CK_ULONG returned = requested;

			if ((ret = PKCS11_HELPER_find_obj(method, lctx->session_handle,
					&obj_handles[total_object_count], &returned)) != 0) {
				ERR_core_raise(handle, ret);
				goto errinit0;
			}

			total_object_count += returned;

			if (returned < requested)
				break;
			
			capacity *= 2;
			CK_OBJECT_HANDLE *new_handles = OPENSSL_realloc(obj_handles, capacity * sizeof(CK_OBJECT_HANDLE));
			if (!new_handles) {
				ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
				goto errinit0;
			}
			obj_handles = new_handles;

		} while (1);

		lctx->buffer_len = total_object_count;
		lctx->next_obj = 0;

		if (total_object_count > 0) {
			lctx->buffer = OPENSSL_malloc(sizeof(PKCS11_STOREMGMT_BUFFER_ENTRY) * total_object_count);
			if (!lctx->buffer) {
				ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
				goto errinit0;
			}
	
			do {
				int j;
				for (j = 0; j < total_object_count; j++) {
					char *label;
					unsigned char *id;
					size_t id_len;
					CK_OBJECT_CLASS obj_class;
					if ((ret = PKCS11_HELPER_get_obj_metadata(method, lctx->session_handle, obj_handles[j],
							&label, &id, &id_len)) != 0) {
						ERR_core_raise(handle, ret);
						goto errinit0;
					}
					if ((ret = PKCS11_HELPER_get_obj_class(method, lctx->session_handle, obj_handles[j],
							&obj_class)) != 0) {
						ERR_core_raise(handle, ret);
						goto errinit0;
					}
					lctx->buffer[j].handle = obj_handles[j];
					lctx->buffer[j].id = id;
					lctx->buffer[j].id_len = id_len;
					lctx->buffer[j].label = label;
					lctx->buffer[j].class = obj_class;
					lctx->buffer[j].read = 0;
				}
	
				break;
			} while(1);
		}

		OPENSSL_free(obj_handles);

		PKCS11_HELPER_find_obj_final(method, lctx->session_handle);
		lctx->initialized = TRUE;
	}

	PKCS11_STOREMGMT_BUFFER_ENTRY *entry;
	while (1) {
		if (lctx->next_obj == lctx->buffer_len) {
			lctx->eof = 1;
			return TRUE;
		}
		entry = &lctx->buffer[lctx->next_obj];
		if (entry->read)
			lctx->next_obj++;
		else
			break;
	}

	entry->read = 1;

	// Find the matching key, if it exists.
	if (entry->class == CKO_PRIVATE_KEY || entry->class == CKO_PUBLIC_KEY) {
		CK_OBJECT_HANDLE priv_key_handle;
		CK_OBJECT_HANDLE pub_key_handle;
		int has_priv_key_handle = 0;
		int has_pub_key_handle = 0;
		CK_OBJECT_CLASS search_obj_class;
		if (entry->class == CKO_PRIVATE_KEY) {
			priv_key_handle = entry->handle;
			has_priv_key_handle = 1;
			search_obj_class = CKO_PUBLIC_KEY;
		} else {
			pub_key_handle = entry->handle;
			has_pub_key_handle = 1;
			search_obj_class = CKO_PRIVATE_KEY;
		}
		int i;
		for (i = lctx->next_obj + 1; i < lctx->buffer_len; i++) {
			if (lctx->buffer[i].read)
				continue;
			if (lctx->buffer[i].class == search_obj_class &&
					entry->id_len == lctx->buffer[i].id_len &&
					memcmp(entry->id, lctx->buffer[i].id, lctx->buffer[i].id_len) == 0) {
				if (search_obj_class == CKO_PRIVATE_KEY) {
					priv_key_handle = lctx->buffer[i].handle;
					has_priv_key_handle = 1;
				} else {
					pub_key_handle = lctx->buffer[i].handle;
					has_pub_key_handle = 1;
				}
				lctx->buffer[i].read = 1;
			}
		}

		CK_ULONG key_type;
		if ((ret = PKCS11_HELPER_get_key_type(method, lctx->session_handle,
				has_pub_key_handle ? pub_key_handle : priv_key_handle, &key_type)) != 0) {
			goto err0;
		}

		char *data_type = key_type == CKK_RSA ? "rsaEncryption" : "EC";

		PKCS11_KEY_REFERENCE key_reference;
		memset(&key_reference, '\0', sizeof(PKCS11_KEY_REFERENCE));

		CK_SESSION_HANDLE session_handle;
		if ((ret = open_session(provctx, lctx->slot_id, &session_handle)) != CKR_OK) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err0;
		}

		key_reference.provctx = lctx->provctx;
		key_reference.session_handle = session_handle;
		if (has_priv_key_handle) {
			key_reference.priv_key_handle = priv_key_handle;
			key_reference.has_priv_key_handle = 1;
		}
		if (has_pub_key_handle) {
			key_reference.pub_key_handle = pub_key_handle;
			key_reference.has_pub_key_handle = 1;
		}

		int object_type = OSSL_OBJECT_PKEY;

		OSSL_PARAM object_params[] = {
			{ OSSL_OBJECT_PARAM_REFERENCE, OSSL_PARAM_OCTET_STRING, &key_reference, sizeof(key_reference), 0},
			{ OSSL_OBJECT_PARAM_TYPE, OSSL_PARAM_INTEGER, &object_type, sizeof(int), 0},
			{ OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_PARAM_UTF8_STRING, data_type, strlen(data_type), 0},
			{ OSSL_OBJECT_PARAM_DESC, OSSL_PARAM_UTF8_STRING, lctx->alias, strlen(lctx->alias), 0},
			OSSL_PARAM_END
		};

		int cb_ret = object_cb(object_params, object_cbarg);

		if (!cb_ret) {
			ERR_core_raise(handle, STORE_OBJECT_CB_ERROR);
			return FALSE;
		}
	} else {
		// TODO implement other objects
		return TRUE;
	}

	return TRUE;

errinit0:
	OPENSSL_free(obj_handles);
errinit1:
	PKCS11_HELPER_find_obj_final(method, lctx->session_handle);
errinit2:
	return FALSE;
err0:
	return FALSE;
}

static int pkcs11_store_eof(void *loaderctx)
{	
	PKCS11_STOREMGMT_LOADER_CTX *lctx = (PKCS11_STOREMGMT_LOADER_CTX *) loaderctx;
	return lctx->eof;
}

static int pkcs11_store_close(void *loaderctx)
{
	PKCS11_STOREMGMT_LOADER_CTX *lctx = (PKCS11_STOREMGMT_LOADER_CTX *) loaderctx;
	
	if (lctx) {
		close_session(lctx->provctx, lctx->session_handle);
		if (lctx->pin)
			OPENSSL_clear_free(lctx->pin, strlen(lctx->pin));
		int i;
		for (i = 0; i < lctx->buffer_len; i++){
			OPENSSL_free(lctx->buffer[i].label);
			OPENSSL_free(lctx->buffer[i].id);
		}
		OPENSSL_free(lctx->buffer);
		OPENSSL_free(lctx);
	}
	return TRUE;
}

static int pkcs11_store_export_obj(void *loaderctx, const void *objref, size_t objref_sz, OSSL_CALLBACK *export_cb,
	void *export_cbarg)
{
	return 0;	
}

const OSSL_DISPATCH pkcs11_store_fns[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void)) pkcs11_store_open},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void)) pkcs11_store_settable_ctx_params},
	{OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void)) pkcs11_store_set_ctx_params},
	{OSSL_FUNC_STORE_LOAD, (void (*)(void)) pkcs11_store_load},
	{OSSL_FUNC_STORE_EOF, (void (*)(void)) pkcs11_store_eof},
	{OSSL_FUNC_STORE_CLOSE, (void (*)(void)) pkcs11_store_close},
    {OSSL_FUNC_STORE_EXPORT_OBJECT, (void (*)(void)) pkcs11_store_export_obj},
    {0, NULL}
};
