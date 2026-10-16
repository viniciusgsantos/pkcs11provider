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
#include "pkcs11provider/session.h"

#include <dlfcn.h>
#include <openssl/core.h>
#include <openssl/params.h>

static OSSL_FUNC_provider_query_operation_fn p_query;
static OSSL_FUNC_provider_get_reason_strings_fn p_reasons;
static OSSL_FUNC_provider_teardown_fn p_teardown;

OSSL_provider_init_fn OSSL_provider_init;

static void provider_ctx_free(PKCS11_PROV_CTX *ctx)
{
	if (ctx) {
		OPENSSL_free(ctx->module_path);
		OPENSSL_free(ctx->pkcs11_init_args);
		OPENSSL_free(ctx->param_functions);
		OPENSSL_free(ctx->error_functions);
		OPENSSL_free(ctx);
	}
}

static PKCS11_PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *handle, PARAMS_FUNCTIONS_ST *params_functions,
	ERROR_FUNCTIONS_ST *error_functions, const char *pkcs11_module_path, const char *pkcs11_init_args)
{
	PKCS11_PROV_CTX *ctx = OPENSSL_malloc(sizeof(PKCS11_PROV_CTX));
	if (!ctx)
		goto err0;

	ctx->core_handle = handle;
	ctx->param_functions = params_functions;
	ctx->error_functions = error_functions;

	ctx->module_handler = NULL;

	ctx->module_path = NULL;
	ctx->pkcs11_init_args = NULL;

	ctx->has_anchor_session = 0;
	ctx->is_logged_in = 0;

	if (pkcs11_module_path == NULL) {
		ERR_core_raise(handle, PROVIDER_MISSING_PKCS11_MODULE_PATH);
		goto err0;
	}
	
	ctx->module_path = OPENSSL_malloc(strlen(pkcs11_module_path) + 1);
	if (!ctx->module_path) {
		ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
		goto err0;
	}
	strcpy(ctx->module_path, pkcs11_module_path);
	
	if (pkcs11_init_args == NULL) {
		ctx->pkcs11_init_args = NULL;
	} else {
		ctx->pkcs11_init_args = OPENSSL_malloc(strlen(pkcs11_init_args) + 1);
		if (!ctx->pkcs11_init_args) {
			ERR_core_raise(handle, MEMORY_ALLOCATION_ERROR);
			goto err0;
		}
		strcpy(ctx->pkcs11_init_args, pkcs11_init_args);
	}

	if ((ctx->module_handler = dlopen(ctx->module_path, RTLD_NOW)) == NULL) {
		ERR_core_raise(handle, PROVIDER_PKCS11_LOAD_MODULE_ERROR);
		goto err0;
	}

	CK_RV (*f_ptr)(CK_FUNCTION_LIST_PTR_PTR);

	if ((f_ptr = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(ctx->module_handler, "C_GetFunctionList")) == NULL) {
		ERR_core_raise(handle, PROVIDER_BAD_PKCS11_MODULE);
		goto err0;
	}

	CK_RV rv = f_ptr(&ctx->method);
	if (rv != CKR_OK) {
		ERR_core_raise(handle, rv);
		goto err0;
	}

	int ret = PKCS11_HELPER_initialize(ctx->method, ctx->pkcs11_init_args);

	if (ret != 0) {
		ERR_core_raise(handle, PROVIDER_FAILED_TO_INITIALIZE_CRYPTOKI);
		goto err0;
	}

	return ctx;

err0:
	if (ctx) {
		if (ctx->module_handler) dlclose(ctx->module_handler);
		OPENSSL_free(ctx->module_path);
		OPENSSL_free(ctx->pkcs11_init_args);
		OPENSSL_free(ctx);
	}
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

	user_logout(ctx);
	ctx->method->C_Finalize(NULL);
	dlclose(ctx->module_handler);
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

	PARAMS_FUNCTIONS_ST *params_functions = OPENSSL_zalloc(sizeof(PARAMS_FUNCTIONS_ST));
	ERROR_FUNCTIONS_ST *error_functions = OPENSSL_zalloc(sizeof(ERROR_FUNCTIONS_ST));
	if (!params_functions || !error_functions) {
		goto err0;
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
		goto err0;
	}

	if ((*provctx = provider_ctx_new(core_handle,
									 params_functions,
									 error_functions,
									 pkcs11_module_path,
									 pkcs11_init_args)) == NULL) {
		goto err0;
	}
	*out = prov_fns;
	return 1;

err0:
	OPENSSL_free(params_functions);
	OPENSSL_free(error_functions);
	return 0;
}
