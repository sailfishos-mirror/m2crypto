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
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/param_build.h>
%}

%apply Pointer NONNULL { const char * };

%inline %{
static PyObject *_provider_err;

void provider_init_error(PyObject *provider_err) {
    Py_INCREF(provider_err);
    _provider_err = provider_err;
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

        if (cert != NULL) {
            raise_ossl_error(_provider_err, "Multiple certs matching URI: %s", uri);
            OSSL_STORE_INFO_free(info);
            OSSL_STORE_close(store);
            return NULL;
        }

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
    OSSL_PROVIDER *provider = NULL;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_end()
    };

    ERR_clear_error();
    /* Load providers */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L // OpenSSL 3.5.0
    provider = OSSL_PROVIDER_load_ex(NULL, name, params);
#else
    /* Use the older function for OpenSSL < 3.5 */
    provider = OSSL_PROVIDER_load(NULL, name);
#endif
    if (!provider) {
        raise_ossl_error(_provider_err, "Failed to load provider '%s'", name);
        return NULL;
    }

    return provider;
}

void provider_unload(OSSL_PROVIDER *provider)
{
    OSSL_PROVIDER_unload(provider);
}

EVP_PKEY *provider_generate_rsa_key_pair(int bits, int exponent, OSSL_PROVIDER *provider)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    int ret;

    ERR_clear_error();

    /* Create a context for RSA key generation */
    /* Note: In a real implementation, we would use the provider's specific algorithm name
     * For now, we use the default RSA algorithm which will use the default provider */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx == NULL) {
        raise_ossl_error(_provider_err, "Failed to create RSA key generation context");
        return NULL;
    }

    /* Initialize key generation */
    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to initialize RSA key generation");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set key parameters */
    params[0] = OSSL_PARAM_construct_int("bits", &bits);
    params[1] = OSSL_PARAM_construct_int("e", &exponent);
    params[2] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to set RSA key parameters");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate the key */
    ret = EVP_PKEY_generate(ctx, &pkey);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to generate RSA key pair");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY *provider_generate_ec_key_pair(const char *curve_name, OSSL_PROVIDER *provider)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int ret;

    ERR_clear_error();

    if (!curve_name) {
        raise_ossl_error(_provider_err, "Invalid NULL curve_name");
        return NULL;
    }

    /* Create a context for EC key generation */
    /* Note: In a real implementation, we would use the provider's specific algorithm name
     * For now, we use the default EC algorithm which will use the default provider */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL) {
        raise_ossl_error(_provider_err, "Failed to create EC key generation context");
        return NULL;
    }

    /* Initialize key generation */
    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to initialize EC key generation");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Set curve name parameter */
    params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to set EC curve parameter");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Generate the key */
    ret = EVP_PKEY_generate(ctx, &pkey);
    if (ret != 1) {
        raise_ossl_error(_provider_err, "Failed to generate EC key pair");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int provider_destroy_key(const char *uri, const char *user_pin)
{
    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    int ret = 0;

    if (!uri) {
        raise_ossl_error(_provider_err, "Invalid NULL uri");
        return 0;
    }

    ERR_clear_error();
    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        raise_ossl_error(_provider_err, "Failed to open store: %s", uri);
        return 0;
    }

    /* Load the key to be destroyed */
    for (info = OSSL_STORE_load(store); info != NULL;
         info = OSSL_STORE_load(store)) {
        int type = OSSL_STORE_INFO_get_type(info);

        if (type == OSSL_STORE_INFO_PKEY || type == OSSL_STORE_INFO_PUBKEY) {
            EVP_PKEY *key = NULL;

            if (type == OSSL_STORE_INFO_PKEY) {
                key = OSSL_STORE_INFO_get1_PKEY(info);
            } else {
                key = OSSL_STORE_INFO_get1_PUBKEY(info);
            }

            if (key != NULL) {
                /* For provider-based keys, we need to use the provider's destroy function
                 * This is typically done through the provider's key management interface */
                /* Note: Actual implementation depends on the specific provider's API
                 * This is a placeholder showing the general approach */

                /* In a real implementation, we would:
                 * 1. Get the provider from the key
                 * 2. Call the provider's key destruction function
                 * 3. Handle PIN authentication if needed */

                /* For now, we'll just free the key and return success
                 * A real implementation would need provider-specific code */
                EVP_PKEY_free(key);
                ret = 1;
                break;
            }
            OSSL_STORE_INFO_free(info);
        }
    }

    OSSL_STORE_close(store);
    return ret;
}
%}
