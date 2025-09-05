# src/M2Crypto/types.py
"""
Type aliases for opaque C structures used in M2Crypto's C-bindings.
"""
from typing import Any, List, NewType

# The base type 'object' is used because these are opaque pointers
# at the Python level. NewType ensures they are treated as distinct types by mypy.
AES_KEY = NewType("AES_KEY", object)
ASN1_BitString = NewType("ASN1_BitString", object)
ASN1_Integer = NewType("ASN1_Integer", object)
ASN1_Object = NewType("ASN1_Object", object)
ASN1_String = NewType("ASN1_String", object)
ASN1_Time = NewType("ASN1_Time", object)
BIGNUM = NewType("BIGNUM", object)
BIO_METHOD = NewType("BIO_METHOD", object)
BIO = NewType("BIO", object)
DH = NewType("DH", object)
DSA = NewType("DSA", object)
DSA_SIG = NewType("DSA_SIG", object)
EC = NewType("EC", object)
EC_KEY = NewType("EC_KEY", object)
ECDSA_SIG = NewType("ECDSA_SIG", object)
ENGINE = NewType("ENGINE", object)
EVP_CIPHER_CTX = NewType("EVP_CIPHER_CTX", object)
EVP_CIPHER = NewType("EVP_CIPHER", object)
EVP_MD_CTX = NewType("EVP_MD_CTX", object)
EVP_MD = NewType("EVP_MD", object)
EVP_PKEY_CTX = NewType("EVP_PKEY_CTX", object)
EVP_PKEY = NewType("EVP_PKEY", object)
HMAC_CTX = NewType("HMAC_CTX", object)
PKCS7 = NewType("PKCS7", object)
RC4_KEY = NewType("RC4_KEY", object)
RSA = NewType("RSA", object)
SSL_CIPHER = NewType("SSL_CIPHER", object)
SSL_CTX = NewType("SSL_CTX", object)
SSL_METHOD = NewType("SSL_METHOD", object)
SSL = NewType("SSL", object)
SSL_SESSION = NewType("SSL_SESSION", object)
X509_CRL = NewType("X509_CRL", object)
X509_EXTENSION = NewType("X509_EXTENSION", object)
X509 = NewType("X509", object)
X509_NAME = NewType("X509_NAME", object)
X509_NAME_ENTRY = NewType("X509_NAME_ENTRY", object)
X509_REQ = NewType("X509_REQ", object)
X509_STORE = NewType("X509_STORE", object)
X509_STORE_CTX = NewType("X509_STORE_CTX", object)
X509V3_CTX = NewType("X509V3_CTX", object)

# Generic STACK_OF type for simplicity
STACK_OF = List[Any]
STACK_OF_X509 = List[X509]
STACK_OF_SSL_CIPHER = List[SSL_CIPHER]
STACK_OF_X509_EXTENSION = List[X509_EXTENSION]
