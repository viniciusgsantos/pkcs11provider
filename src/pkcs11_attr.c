#include "pkcs11provider/pkcs11_attr.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

CK_ATTRIBUTE makeBooleanAttribute(CK_ATTRIBUTE_TYPE type, int value)
{
	CK_BBOOL *boolValue = (CK_BBOOL *) OPENSSL_malloc(sizeof(CK_BBOOL));
	*boolValue = value ? CK_TRUE : CK_FALSE;

	CK_ATTRIBUTE boolAttr;
	boolAttr.type = type;
	boolAttr.pValue = boolValue;
	boolAttr.ulValueLen = sizeof(CK_BBOOL);

	return boolAttr;
}

CK_ATTRIBUTE makeUnsignedLongAttribute(CK_ATTRIBUTE_TYPE type, unsigned long value)
{
	CK_ULONG *uLongValue = (CK_ULONG *) OPENSSL_malloc(sizeof(CK_ULONG));
	*uLongValue = value;

	CK_ATTRIBUTE uLongAttr;
	uLongAttr.type = type;
	uLongAttr.pValue = uLongValue;
	uLongAttr.ulValueLen = sizeof(CK_ULONG);

	return uLongAttr;
}

CK_ATTRIBUTE makeCharArrayAttribute(CK_ATTRIBUTE_TYPE type, const CK_BYTE *value, unsigned long len)
{
	CK_BYTE *charArrayValue = (CK_BYTE *) OPENSSL_malloc(len);
	memcpy(charArrayValue, value, len);

	CK_ATTRIBUTE charArrayAttr;
	charArrayAttr.type = type;
	charArrayAttr.pValue = charArrayValue;
	charArrayAttr.ulValueLen = len;

	return charArrayAttr;
}

CK_ATTRIBUTE makeUTF8Attribute(CK_ATTRIBUTE_TYPE type, const char *value)
{
	size_t valueLen = strlen(value);
	CK_UTF8CHAR *utf8Value = (CK_UTF8CHAR *) OPENSSL_malloc(valueLen + 1);
	OPENSSL_strlcpy(utf8Value, value, valueLen + 1);

	CK_ATTRIBUTE utf8Attribute;
	utf8Attribute.type = type;
	utf8Attribute.pValue = utf8Value;
	utf8Attribute.ulValueLen = valueLen;

	return utf8Attribute;
}

CK_ATTRIBUTE makeObjectClassAttribute(CK_ATTRIBUTE_TYPE type, CK_OBJECT_CLASS objClass)
{
	CK_OBJECT_CLASS *objClassInternal = (CK_OBJECT_CLASS *) OPENSSL_malloc(sizeof(CK_OBJECT_CLASS));
	*objClassInternal = objClass;

	CK_ATTRIBUTE objectClassAttr;
	objectClassAttr.type = type;
	objectClassAttr.pValue = objClassInternal;
	objectClassAttr.ulValueLen = sizeof(CK_OBJECT_CLASS);

	return objectClassAttr;
}

CK_ATTRIBUTE toCharArrayAttribute(CK_ATTRIBUTE_TYPE type, CK_BYTE **value, unsigned long len)
{
	CK_ATTRIBUTE charArrayAttr;
	charArrayAttr.type = type;
	charArrayAttr.pValue = *value;
	charArrayAttr.ulValueLen = len;

	*value = NULL;

	return charArrayAttr;
}

void free_attributes_data(CK_ATTRIBUTE_PTR attributes, unsigned int attributes_size)
{	
	int i = attributes_size;
	while (i--) {
		if (attributes[i].pValue) {
			OPENSSL_free(attributes[i].pValue);
			attributes[i].pValue = NULL;
			attributes[i].ulValueLen = 0;
		}
	}
}

int check_attributes_data(CK_ATTRIBUTE_PTR attributes, unsigned int attributes_size) {
	int i = attributes_size;
	while (i--) {
		if (!attributes[i].pValue) {
			return 0;
		}
	}
	return 1;
}
