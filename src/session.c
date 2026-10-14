#include "pkcs11provider/session.h"
#include "pkcs11provider/pkcs11_core_functions.h"
#include "pkcs11provider/pkcs11_errors.h"

#include <string.h>

int open_session(PKCS11_PROV_CTX *provctx, const CK_SLOT_ID slot_id, CK_SESSION_HANDLE *session_handle)
{
    CK_RV rv;

    if (!provctx->has_anchor_session)
        open_anchor_session(provctx, slot_id);
    
    if ((rv = PKCS11_open_session(provctx->method, slot_id, session_handle)) != 0) {
        return rv;
    }

    return 0;
}

int close_session(PKCS11_PROV_CTX *provctx, CK_SESSION_HANDLE session_handle)
{
    CK_RV rv;

    if ((rv = PKCS11_close_session(provctx->method, session_handle)) != 0) {
        return rv;
    }
}

int user_login(PKCS11_PROV_CTX *provctx, const char *user_pin)
{
    CK_RV rv;
    
    if (!provctx->has_anchor_session) {
        return NO_ANCHOR_SESSION_LOGIN_ERROR;
    }
    
    if (!provctx->is_logged_in) {
        if ((rv = PKCS11_login(provctx->method, provctx->anchor_session, user_pin)) != 0) {
            return rv;
        }
        provctx->is_logged_in = 1;
    }

    return 0;
}

int user_logout(PKCS11_PROV_CTX *provctx)
{
    CK_RV rv;

    if (!provctx->has_anchor_session) {
        return NO_ANCHOR_SESSION_LOGOUT_ERROR;
    }

    if (provctx->is_logged_in) {
        if ((rv = PKCS11_logout(provctx->method, provctx->anchor_session)) != 0) {
            return rv;
        }
        provctx->is_logged_in = 0;
    }

    return 0;
}

static int open_anchor_session(PKCS11_PROV_CTX *provctx, const CK_SLOT_ID slot_id)
{
    if (!provctx->has_anchor_session) {
        CK_RV rv;
        if ((rv = PKCS11_open_session(provctx->method, slot_id, &provctx->anchor_session)) != 0) {
			return rv;
        }

        provctx->has_anchor_session = 1;
    }

    return 0;
}

static int PKCS11_open_session(CK_FUNCTION_LIST_PTR method, const CK_SLOT_ID slot_id,
    CK_SESSION_HANDLE *session_handle)
{
	CK_RV rv = method->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, session_handle);

	if (rv != CKR_OK)
		return rv;

	return 0;
}

static int PKCS11_close_session(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = method->C_CloseSession(session_handle);

	if(rv != CKR_OK)
		return rv;

	return 0;
}

static int PKCS11_login(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle,
		const char *user_pin)
{
	CK_RV rv = method->C_Login(session_handle, CKU_USER, (unsigned char *)user_pin, strlen(user_pin));
	
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		return rv;
	
	return 0;
}

static int PKCS11_logout(CK_FUNCTION_LIST_PTR method, CK_SESSION_HANDLE session_handle)
{
	CK_RV rv = method->C_Logout(session_handle);

	if(rv != CKR_OK)
		return rv;

	return 0;
}