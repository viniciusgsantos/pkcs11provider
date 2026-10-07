#ifndef PKCS11_ATTR_H_
#define PKCS11_ATTR_H_

#include "pkcs11provider/pkcs11/pkcs11.h"

CK_ATTRIBUTE makeBooleanAttribute(CK_ATTRIBUTE_TYPE type, int value);
CK_ATTRIBUTE makeUnsignedLongAttribute(CK_ATTRIBUTE_TYPE type, unsigned long value);
CK_ATTRIBUTE makeCharArrayAttribute(CK_ATTRIBUTE_TYPE type, const CK_BYTE *value, unsigned long len);
CK_ATTRIBUTE makeUTF8Attribute(CK_ATTRIBUTE_TYPE type, const char *value);
CK_ATTRIBUTE makeObjectClassAttribute(CK_ATTRIBUTE_TYPE type, CK_OBJECT_CLASS objClass);

CK_ATTRIBUTE toCharArrayAttribute(CK_ATTRIBUTE_TYPE type, CK_BYTE **value, unsigned long len);

void free_attributes_data(CK_ATTRIBUTE_PTR attributes, unsigned int attributes_size);
int check_attributes_data(CK_ATTRIBUTE_PTR attributes, unsigned int attributes_size);


#endif /* PKCS11_ATTR_H_ */
