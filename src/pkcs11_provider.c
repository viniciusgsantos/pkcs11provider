#include "pkcs11provider/pkcs11_attr.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_errors.h"
#include "pkcs11provider/pkcs11_ec_keymgmt.h"
#include "pkcs11provider/pkcs11_ec_sig.h"
#include "pkcs11provider/pkcs11_helper.h"
#include "pkcs11provider/pkcs11_rsa_keymgmt.h"
#include "pkcs11provider/pkcs11_rsa_sig.h"
#include "pkcs11provider/pkcs11_store.h"
#include "pkcs11provider/pkcs11_types.h"

#include <dlfcn.h>
#include <openssl/core.h>
#include <openssl/params.h>

static OSSL_FUNC_provider_query_operation_fn p_query;
static OSSL_FUNC_provider_get_reason_strings_fn p_reasons;
static OSSL_FUNC_provider_teardown_fn p_teardown;

OSSL_provider_init_fn OSSL_provider_init;

static void provider_ctx_free(PKCS11_PROV_CTX *ctx)
{
	OPENSSL_free(ctx);
}

static PKCS11_PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *handle, const char *pkcs11_module_path,
	const char *pkcs11_init_args)
{
	PKCS11_PROV_CTX *ctx;

	if ((ctx = OPENSSL_malloc(sizeof(PKCS11_PROV_CTX))) != NULL) {
		ctx->core_handle = handle;
		if (pkcs11_module_path == NULL)
			goto err1;
		ctx->module_path = OPENSSL_zalloc(strlen(pkcs11_module_path) + 1);
		strcpy(ctx->module_path, pkcs11_module_path);
		if (pkcs11_init_args == NULL) {
			ctx->pkcs11_init_args = NULL;
		} else {
			ctx->pkcs11_init_args = OPENSSL_zalloc(strlen(pkcs11_init_args) + 1);
			strcpy(ctx->pkcs11_init_args, pkcs11_init_args);
		}
	} else {
		goto err1;
	}

	int ret;

	CK_RV rv;
	if ((ctx->module_handler = dlopen(ctx->module_path, RTLD_NOW)) == NULL) {
		ERR_core_raise(handle, PROVIDER_PKCS11_LOAD_MODULE_ERROR);
		goto err1;
	}

	CK_RV (*f_ptr)(CK_FUNCTION_LIST_PTR_PTR);

	if ((f_ptr = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(ctx->module_handler, "C_GetFunctionList")) == NULL) {
		ERR_core_raise(handle, PROVIDER_BAD_PKCS11_MODULE);
		goto err0;
	}

	rv = f_ptr(&ctx->method);
	if (rv != CKR_OK) {
		ERR_core_raise(handle, rv);
		goto err0;
	}

	ret = PKCS11_HELPER_initialize(ctx->method, ctx->pkcs11_init_args);

	if (ret != 0) {
		ctx->pkcs11_initialized = FALSE;
		dlclose(ctx->module_handler);
		ctx->module_handler = NULL;
		return NULL;
	} else {
		ctx->pkcs11_initialized = TRUE;
	}

	return ctx;

err0:
	dlclose(ctx->module_handler);
	ctx->module_handler = NULL;
	ERR_core_raise(handle, ret);
err1:
	return NULL;

}

static const OSSL_ALGORITHM signature_algorithms[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=pkcs11", pkcs11_rsa_fns },
	{ "EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=pkcs11", pkcs11_ec_fns },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM keymgmt_algorithms[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=pkcs11", pkcs11_rsa_keymgmt_fns },
	{ "EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=pkcs11", pkcs11_ec_keymgmt_fns },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM store_algorithms[] = {
	{ "pkcs11", "provider=pkcs11", pkcs11_store_fns },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *p_query(void *provctx, int operation_id,
									 int *no_store)
{
	*no_store = 0;
	switch (operation_id) {
	case OSSL_OP_SIGNATURE:
		return signature_algorithms;
	case OSSL_OP_KEYMGMT:
		return keymgmt_algorithms;
	case OSSL_OP_STORE:
		return store_algorithms;
	}
	return NULL;
}

static const OSSL_ITEM *p_reasons(void *provctx)
{
	return reasons;
}

static void p_teardown(void *provctx)
{
	if (provctx == NULL)
		return;

	PKCS11_PROV_CTX *ctx = (PKCS11_PROV_CTX *) provctx;


	if (ctx->pkcs11_initialized) {
		ctx->method->C_Finalize(NULL);
		ctx->pkcs11_initialized = FALSE;
	}

	if (ctx->module_handler) {
		dlclose(ctx->module_handler);
		ctx->module_handler = NULL;
		ctx->method = NULL;
	}

	if (ctx->module_path) {
		OPENSSL_free(ctx->module_path);
		ctx->module_path = NULL;
	}

	if (ctx->pkcs11_init_args) {
		OPENSSL_free(ctx->pkcs11_init_args);
		ctx->pkcs11_init_args = NULL;
	}

	free(ctx);
}

static const OSSL_DISPATCH prov_fns[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) p_teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) p_query },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void)) p_reasons },
	{ 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core_handle,
					   const OSSL_DISPATCH *in,
					   const OSSL_DISPATCH **out,
					   void **provctx)
{
	OSSL_FUNC_core_gettable_params_fn *core_gettable_params = NULL;
	OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
	OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
	OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
	OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;

	for(; in->function_id != 0; in++) {
		switch (in->function_id) {
		case OSSL_FUNC_CORE_GETTABLE_PARAMS:
			core_gettable_params = OSSL_FUNC_core_gettable_params(in);
			break;
		case OSSL_FUNC_CORE_GET_PARAMS:
			core_get_params = OSSL_FUNC_core_get_params(in);
			break;
		 case OSSL_FUNC_CORE_NEW_ERROR:
			core_new_error = OSSL_FUNC_core_new_error(in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			core_vset_error = OSSL_FUNC_core_vset_error(in);
			break;
		default:
			/* Ignore what we don't know */
			break;
		}
	}

	init_error_functions(core_new_error, core_set_error_debug, core_vset_error);
	init_get_params_functions(core_gettable_params, core_get_params);

	static char *pkcs11_module_path = NULL;
	static char *pkcs11_init_args = NULL;

	static OSSL_PARAM counter_request[] = {
		{ "pkcs11-module-path", OSSL_PARAM_UTF8_PTR,
			&pkcs11_module_path, sizeof(&pkcs11_module_path), 0 },
		{ "pkcs11-init-args", OSSL_PARAM_UTF8_PTR,
			&pkcs11_init_args, sizeof(&pkcs11_init_args), 0 },
		OSSL_PARAM_END
	};

	if (!core_get_params(core_handle, counter_request)) {
		return 0;
	}

	if ((*provctx = provider_ctx_new(core_handle, pkcs11_module_path, pkcs11_init_args)) == NULL)
		return 0;
	*out = prov_fns;
	return 1;
}
