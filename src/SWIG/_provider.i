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

    if ((strncmp(uri, "pkcs11:", 7) == 0)
        && strstr(uri, "type=private") == NULL) {
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
            OSSL_STORE_close(store);
            return NULL;
        }

        switch (type) {
        case OSSL_STORE_INFO_PUBKEY:
            key = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            key = OSSL_STORE_INFO_get1_PKEY(info);
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
            OSSL_STORE_close(store);
            return NULL;
        }

        switch (type) {
        case OSSL_STORE_INFO_CERT:
            cert = OSSL_STORE_INFO_get1_CERT(info);
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
%}
