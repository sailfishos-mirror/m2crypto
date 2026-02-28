/*
 * Portions of this code are derived from tests/util.c in the pkcs11-provider project,
 * with permission granted by Simo Sorce for reuse in this file.
 */

%{
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/store.h>

/* OpenSSL PROVIDER APIs exist only in OpenSSL >= 3.0. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/params.h>
#else
typedef void OSSL_PROVIDER;
#endif
%}

%apply Pointer NONNULL { const char * };

%inline %{
static PyObject *_provider_err;

void provider_init_error(PyObject *provider_err) {
    Py_INCREF(provider_err);
    _provider_err = provider_err;
}


static PyObject *provider_exc(void)
{
    return _provider_err ? _provider_err : PyExc_RuntimeError;
}


static void raise_ossl_error(PyObject *exc, const char *fmt, ...)
{
    char msg[512];
    va_list ap;

    if (!exc) {
        exc = PyExc_RuntimeError;
    }

    /* Format the user-provided message */
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Get the topmost OpenSSL error (if any) */
    unsigned long err = ERR_get_error();
    if (err) {
        char errbuf[256];
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        PyErr_Format(exc, "%s: %s", msg, errbuf);
    } else {
        PyErr_SetString(exc, msg);
    }
}

EVP_PKEY *provider_load_key(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *key = NULL;
    int want_private = 0;
    int want_public = 0;

    if (!uri) {
        raise_ossl_error(_provider_err, "Invalid NULL uri");
        return NULL;
    }

    ERR_clear_error();
    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        raise_ossl_error(_provider_err, "Failed to open store: %s", uri);
        return NULL;
    }

    want_private = (strstr(uri, "type=private") != NULL);
    want_public = (strstr(uri, "type=public") != NULL);

    /* Hint the expected object type when the URI is explicit. */
    if (want_private) {
        if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY) != 1) {
            raise_ossl_error(_provider_err, "Failed to expect Private Key");
            OSSL_STORE_close(store);
            return NULL;
        }
    } else if (want_public) {
        if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PUBKEY) != 1) {
            raise_ossl_error(_provider_err, "Failed to expect Public Key");
            OSSL_STORE_close(store);
            return NULL;
        }
    }

    if ((strncmp(uri, "pkcs11:", 7) == 0)
        && !want_private && !want_public) {
        /* This is a workaround for OpenSSL < 3.2.0 where the code fails
         * to correctly source public keys unless explicitly requested
         * via an expect hint */
        if (OSSL_STORE_expect(store, OSSL_STORE_INFO_PUBKEY) != 1) {
            raise_ossl_error(_provider_err, "Failed to expect Public Key File");
            OSSL_STORE_close(store);
            return NULL;
        }
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (key != NULL) {
            PyErr_Format(_provider_err, "Multiple keys matching URI: %s", uri);
            OSSL_STORE_INFO_free(info);
            OSSL_STORE_close(store);
            return NULL;
        }

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            if (want_private) {
                /* Some stores may also yield the public key for a private-key URI. */
                break;
            }
            if (key != NULL) {
                PyErr_Format(provider_exc(), "Multiple keys matching URI: %s", uri);
                OSSL_STORE_INFO_free(info);
                OSSL_STORE_close(store);
                return NULL;
            }
            key = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            if (want_public) {
                /* Ignore private keys when the URI explicitly asks for public key. */
                break;
            }
            if (key != NULL) {
                PyErr_Format(provider_exc(), "Multiple keys matching URI: %s", uri);
                OSSL_STORE_INFO_free(info);
                OSSL_STORE_close(store);
                return NULL;
            }
            key = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        default:
            /* Ignore unrelated objects returned by the store. */
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (key == NULL) {
        raise_ossl_error(_provider_err,
                         "Failed to load key from URI: %s", uri);
    }
    OSSL_STORE_close(store);

    return key;
}

X509 *provider_load_certificate(const char *uri)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    X509 *cert = NULL;

    if (!uri) {
        raise_ossl_error(_provider_err, "Invalid NULL uri");
        return NULL;
    }

    ERR_clear_error();
    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        raise_ossl_error(_provider_err, "Failed to open store: %s", uri);
        return NULL;
    }

    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        switch (type) {
        case OSSL_STORE_INFO_CERT:
            if (cert != NULL) {
                raise_ossl_error(provider_exc(),
                                 "Multiple certs matching URI: %s", uri);
                OSSL_STORE_INFO_free(info);
                OSSL_STORE_close(store);
                return NULL;
            }
            cert = OSSL_STORE_INFO_get1_CERT(info);
            break;
        default:
            /* Ignore non-certificate objects returned by the store. */
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (cert == NULL) {
        raise_ossl_error(_provider_err, "Failed to load cert from URI: %s", uri);
    }
    OSSL_STORE_close(store);

    return cert;
}

OSSL_PROVIDER *provider_load(const char *name)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    (void)name;
    PyErr_SetString(provider_exc(), "OpenSSL provider API requires OpenSSL >= 3.0");
    return NULL;
#else
    OSSL_PROVIDER *provider = NULL;

    ERR_clear_error();
    /* Load providers */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L // OpenSSL 3.5.0
    provider = OSSL_PROVIDER_load_ex(NULL, name, NULL);
#else
    /* Use the older function for OpenSSL < 3.5 */
    provider = OSSL_PROVIDER_load(NULL, name);
#endif
    if (!provider) {
        raise_ossl_error(provider_exc(), "Failed to load provider '%s'", name);
        return NULL;
    }

    return provider;
#endif
}

void provider_unload(OSSL_PROVIDER *provider)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    (void)provider;
    PyErr_SetString(provider_exc(), "OpenSSL provider API requires OpenSSL >= 3.0");
#else
    OSSL_PROVIDER_unload(provider);
#endif
}

EVP_PKEY *provider_generate_rsa_key_pair(int bits, int exponent, OSSL_PROVIDER *provider)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    (void)bits;
    (void)exponent;
    (void)provider;
    PyErr_SetString(provider_exc(), "Key generation requires OpenSSL >= 3.0");
    return NULL;
#else
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    int ret;
    size_t nbits = (size_t)bits;
    char propq[128];
    const char *pname = NULL;

    if (provider == NULL) {
        PyErr_SetString(provider_exc(), "Invalid NULL provider");
        return NULL;
    }

    pname = OSSL_PROVIDER_get0_name(provider);
    if (pname == NULL) {
        PyErr_SetString(provider_exc(), "Failed to get provider name");
        return NULL;
    }

    snprintf(propq, sizeof(propq), "provider=%s", pname);

    ERR_clear_error();

    /* Create a context for RSA key generation from the requested provider. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", propq);
    if (ctx == NULL) {
        raise_ossl_error(provider_exc(), "Failed to create RSA key generation context");
        return NULL;
    }

    /* Initialize key generation */
    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to initialize RSA key generation");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set key parameters */
    params[0] = OSSL_PARAM_construct_size_t("bits", &nbits);
    {
        unsigned int eword = (unsigned int)exponent;
        unsigned char ebuf[sizeof(unsigned int)];
        size_t elen = 0;

        if (eword == 0) {
            raise_ossl_error(provider_exc(), "Invalid RSA exponent: %d", exponent);
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }

        while (eword != 0 && elen < sizeof(ebuf)) {
            ebuf[sizeof(ebuf) - 1 - elen] = (unsigned char)(eword & 0xffU);
            eword >>= 8;
            elen++;
        }
        params[1] = OSSL_PARAM_construct_BN("e", ebuf + sizeof(ebuf) - elen, elen);
    }
    params[2] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to set RSA key parameters");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate the key */
    ret = EVP_PKEY_generate(ctx, &pkey);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to generate RSA key pair");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
#endif
}

EVP_PKEY *provider_generate_ec_key_pair(const char *curve_name, OSSL_PROVIDER *provider)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    (void)curve_name;
    (void)provider;
    PyErr_SetString(provider_exc(), "Key generation requires OpenSSL >= 3.0");
    return NULL;
#else
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int ret;
    char propq[128];
    const char *pname = NULL;

    ERR_clear_error();

    if (!curve_name) {
        raise_ossl_error(provider_exc(), "Invalid NULL curve_name");
        return NULL;
    }

    if (provider == NULL) {
        PyErr_SetString(provider_exc(), "Invalid NULL provider");
        return NULL;
    }

    pname = OSSL_PROVIDER_get0_name(provider);
    if (pname == NULL) {
        PyErr_SetString(provider_exc(), "Failed to get provider name");
        return NULL;
    }

    snprintf(propq, sizeof(propq), "provider=%s", pname);

    /* Create a context for EC key generation from the requested provider. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", propq);
    if (ctx == NULL) {
        raise_ossl_error(provider_exc(), "Failed to create EC key generation context");
        return NULL;
    }

    /* Initialize key generation */
    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to initialize EC key generation");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set curve name parameter */
    params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to set EC curve parameter");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate the key */
    ret = EVP_PKEY_generate(ctx, &pkey);
    if (ret != 1) {
        raise_ossl_error(provider_exc(), "Failed to generate EC key pair");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
#endif
}

int provider_destroy_key(const char *uri, const char *user_pin)
{
    (void)uri;
    (void)user_pin;
    PyErr_SetString(PyExc_NotImplementedError,
                    "Provider key destruction is provider-specific and is not implemented");
    return 0;
}
%}
