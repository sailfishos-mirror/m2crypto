/* Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>

PyObject *dsa_sig_get_r(DSA_SIG *dsa_sig) {
    const BIGNUM* pr;
    DSA_SIG_get0(dsa_sig, &pr, NULL);
    return bn_to_mpi(pr);
}

PyObject *dsa_sig_get_s(DSA_SIG *dsa_sig) {
    const BIGNUM* qs;
    DSA_SIG_get0(dsa_sig, NULL, &qs);
    return bn_to_mpi(qs);
}
%}

%apply Pointer NONNULL { DSA * };

%rename(dsa_new) DSA_new;
extern DSA *DSA_new(void);
%rename(dsa_free) DSA_free;
extern void DSA_free(DSA *);
%rename(dsa_size) DSA_size;
extern int DSA_size(const DSA *); /* assert(dsa->q); */
%rename(dsa_gen_key) DSA_generate_key;
extern int DSA_generate_key(DSA *);

%warnfilter(454) _dsa_err;
%inline %{
static PyObject *_dsa_err;

void dsa_init(PyObject *dsa_err) {
    Py_INCREF(dsa_err);
    _dsa_err = dsa_err;
}
%}

%typemap(out) DSA * {
    PyObject *self = NULL; /* bug in SWIG_NewPointerObj as of 3.0.5 */

    if ($1 != NULL)
        $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
    else {
        $result = NULL;
    }
}
%inline %{
DSA *dsa_generate_parameters(int bits, PyObject *pyfunc) {
    DSA *dsa;
    BN_GENCB *gencb;
    int ret;

    if ((gencb=BN_GENCB_new()) == NULL) {
        m2_PyErr_Msg(_dh_err);
        return NULL;
    }

    if ((dsa = DSA_new()) == NULL) {
        m2_PyErr_Msg(_dsa_err);
        BN_GENCB_free(gencb);
        return NULL;
    }

    BN_GENCB_set(gencb, bn_gencb_callback, (void *) pyfunc);

    Py_INCREF(pyfunc);
    ret = DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL,
                                     gencb);
    Py_DECREF(pyfunc);
    BN_GENCB_free(gencb);

    if (ret)
        return dsa;

    m2_PyErr_Msg(_dsa_err);
    DSA_free(dsa);
    return NULL;
}

DSA *dsa_read_params(BIO *f, PyObject *pyfunc) {
    DSA *ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_read_bio_DSAparams(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);

    if (ret == NULL) {
        m2_PyErr_Msg(_dsa_err);
    }

    return ret;
}

DSA *dsa_read_key(BIO *f, PyObject *pyfunc) {
    DSA *ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_read_bio_DSAPrivateKey(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);

    if (ret == NULL) {
        m2_PyErr_Msg(_dsa_err);
    }

    return ret;
}

DSA *dsa_read_pub_key(BIO *f, PyObject *pyfunc) {
    DSA *ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_read_bio_DSA_PUBKEY(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);

    if (ret == NULL) {
        m2_PyErr_Msg(_dsa_err);
    }

    return ret;
}
%}
%typemap(out) DSA * ;

%inline %{
PyObject *dsa_get_p(DSA *dsa) {
    const BIGNUM* p = NULL;
    DSA_get0_pqg(dsa, &p, NULL, NULL);
    if (!p) {
        PyErr_SetString(_dsa_err, "'p' is unset");
        return NULL;
    }
    return bn_to_mpi(p);
}

PyObject *dsa_get_q(DSA *dsa) {
    const BIGNUM* q = NULL;
    DSA_get0_pqg(dsa, NULL, &q, NULL);
    if (!q) {
        PyErr_SetString(_dsa_err, "'q' is unset");
        return NULL;
    }
    return bn_to_mpi(q);
}

PyObject *dsa_get_g(DSA *dsa) {
    const BIGNUM* g = NULL;
    DSA_get0_pqg(dsa, NULL, NULL, &g);
    if (!g) {
        PyErr_SetString(_dsa_err, "'g' is unset");
        return NULL;
    }
    return bn_to_mpi(g);
}

PyObject *dsa_get_pub(DSA *dsa) {
    const BIGNUM* pub_key = NULL;
    DSA_get0_key(dsa, &pub_key, NULL);
    if (!pub_key) {
        PyErr_SetString(_dsa_err, "'pub' is unset");
        return NULL;
    }
    return bn_to_mpi(pub_key);
}

PyObject *dsa_get_priv(DSA *dsa) {
    const BIGNUM* priv_key = NULL;
    DSA_get0_key(dsa, NULL, &priv_key);
    if (!priv_key) {
        PyErr_SetString(_dsa_err, "'priv' is unset");
        return NULL;
    }
    return bn_to_mpi(priv_key);
}

PyObject *dsa_set_pqg(DSA *dsa, PyObject *pval, PyObject* qval, PyObject* gval) {
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* g = NULL;
    Py_buffer pbuf, qbuf, gbuf;

    /* --- Process P (Prime) --- */
    if (m2_PyObject_GetBufferInt(pval, &pbuf, PyBUF_SIMPLE) != -1) {
        if (!(p = BN_mpi2bn((unsigned char *)pbuf.buf, pbuf.len, NULL))) {
            PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
            m2_PyBuffer_Release(pval, &pbuf);
            return NULL;
        }
        m2_PyBuffer_Release(pval, &pbuf);
    } else {
        PyErr_Clear();
    }
    if (p == NULL) {
        if (!(p = m2_PyObject_AsBIGNUM(pval, _dsa_err))) {
            return NULL;
        }
    }

    /* --- Process Q (Subprime) --- */
    if (m2_PyObject_GetBufferInt(qval, &qbuf, PyBUF_SIMPLE) != -1) {
        if (!(q = BN_mpi2bn((unsigned char *)qbuf.buf, qbuf.len, NULL))) {
            PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
            m2_PyBuffer_Release(qval, &qbuf);
            BN_free(p); /* Cleanup previous */
            return NULL;
        }
        m2_PyBuffer_Release(qval, &qbuf);
    } else {
        PyErr_Clear();
    }
    if (q == NULL) {
        if (!(q = m2_PyObject_AsBIGNUM(qval, _dsa_err))) {
            BN_free(p); /* Cleanup previous */
            return NULL;
        }
    }

    /* --- Process G (Generator) --- */
    if (m2_PyObject_GetBufferInt(gval, &gbuf, PyBUF_SIMPLE) != -1) {
        if (!(g = BN_mpi2bn((unsigned char *)gbuf.buf, gbuf.len, NULL))) {
            PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
            m2_PyBuffer_Release(gval, &gbuf);
            BN_free(p); BN_free(q); /* Cleanup previous */
            return NULL;
        }
        m2_PyBuffer_Release(gval, &gbuf);
    } else {
        PyErr_Clear();
    }
    if (g == NULL) {
        if (!(g = m2_PyObject_AsBIGNUM(gval, _dsa_err))) {
            BN_free(p); BN_free(q); /* Cleanup previous */
            return NULL;
        }
    }

    /* --- Set parameters using OpenSSL 1.1.0+ API --- */
    if (!DSA_set0_pqg(dsa, p, q, g)) {
        PyErr_SetString(
            _dsa_err,
            "Cannot set prime number, subprime, or generator of subgroup for DSA.");
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *dsa_set_pub(DSA *dsa, PyObject *value) {
    BIGNUM *bn;
    Py_buffer vbuf;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
        return NULL;

    if (!(bn = BN_mpi2bn((unsigned char *)vbuf.buf, vbuf.len, NULL))) {
        m2_PyErr_Msg(_dsa_err);
        m2_PyBuffer_Release(value, &vbuf);
        return NULL;
    }
    m2_PyBuffer_Release(value, &vbuf);
    if (!DSA_set0_key(dsa, bn, NULL)) {
        BN_free(bn);
        PyErr_SetString(_dsa_err, "Cannot set private and public key for DSA.");
    }
    Py_RETURN_NONE;
}
%}

%threadallow dsa_write_params_bio;
%inline %{
int dsa_write_params_bio(DSA* dsa, BIO* f) {
    return PEM_write_bio_DSAparams(f, dsa);
}
%}

%inline %{
int dsa_write_key_bio(DSA* dsa, BIO* f, EVP_CIPHER *cipher, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_write_bio_DSAPrivateKey(f, dsa, cipher, NULL, 0,
                                        passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);
    return ret;
}
%}

%inline %{
int dsa_write_key_bio_no_cipher(DSA* dsa, BIO* f, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_write_bio_DSAPrivateKey(f, dsa, NULL, NULL, 0,
                                        passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);
    return ret;
}
%}

%threadallow dsa_write_pub_key_bio;
%inline %{
int dsa_write_pub_key_bio(DSA* dsa, BIO* f) {
    return PEM_write_bio_DSA_PUBKEY(f, dsa);
}
%}

%inline %{
PyObject *dsa_sign(DSA *dsa, PyObject *value) {
    Py_buffer vbuf;
    PyObject *tuple;
    DSA_SIG *sig;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
        return NULL;

    if (!(sig = DSA_do_sign(vbuf.buf, vbuf.len, dsa))) {
        m2_PyErr_Msg(_dsa_err);
        m2_PyBuffer_Release(value, &vbuf);
        return NULL;
    }
    if (!(tuple = PyTuple_New(2))) {
        DSA_SIG_free(sig);
        PyErr_SetString(PyExc_RuntimeError, "PyTuple_New() fails");
        m2_PyBuffer_Release(value, &vbuf);
        return NULL;
    }
    PyTuple_SET_ITEM(tuple, 0, dsa_sig_get_r(sig));
    PyTuple_SET_ITEM(tuple, 1, dsa_sig_get_s(sig));
    DSA_SIG_free(sig);
    m2_PyBuffer_Release(value, &vbuf);
    return tuple;
}

int dsa_verify(DSA *dsa, PyObject *value, PyObject *r, PyObject *s) {
    Py_buffer vbuf, rbuf, sbuf;
    DSA_SIG *sig;
    BIGNUM* pr, *ps;
    int ret;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
        return -1;
    if (m2_PyObject_GetBufferInt(r, &rbuf, PyBUF_SIMPLE) == -1) {
        m2_PyBuffer_Release(value, &vbuf);
        return -1;
    }
    if (m2_PyObject_GetBufferInt(s, &sbuf, PyBUF_SIMPLE) == -1) {
        m2_PyBuffer_Release(value, &vbuf);
        m2_PyBuffer_Release(r, &rbuf);
        return -1;
    }

    if (!(sig = DSA_SIG_new())) {
        m2_PyErr_Msg(_dsa_err);
        m2_PyBuffer_Release(value, &vbuf);
        m2_PyBuffer_Release(r, &rbuf);
        m2_PyBuffer_Release(s, &sbuf);
        return -1;
    }
    pr = BN_mpi2bn((unsigned char *)rbuf.buf, rbuf.len, NULL);
    if (!pr) {
        m2_PyErr_Msg(_dsa_err);
        DSA_SIG_free(sig);
        m2_PyBuffer_Release(value, &vbuf);
        m2_PyBuffer_Release(r, &rbuf);
        m2_PyBuffer_Release(s, &sbuf);
        return -1;
    }
    ps = BN_mpi2bn((unsigned char *)sbuf.buf, sbuf.len, NULL);
    if (!ps) {
        m2_PyErr_Msg(_dsa_err);
        DSA_SIG_free(sig);
        m2_PyBuffer_Release(value, &vbuf);
        m2_PyBuffer_Release(r, &rbuf);
        m2_PyBuffer_Release(s, &sbuf);
        BN_free(pr);
        return -1;
    }
    if (!DSA_SIG_set0(sig, pr, ps)) {
        m2_PyErr_Msg(_dsa_err);
        DSA_SIG_free(sig);
        m2_PyBuffer_Release(value, &vbuf);
        m2_PyBuffer_Release(r, &rbuf);
        m2_PyBuffer_Release(s, &sbuf);
        BN_free(pr);
        BN_free(ps);
        return -1;
    }

    ret = DSA_do_verify(vbuf.buf, vbuf.len, sig, dsa);
    DSA_SIG_free(sig);
    if (ret == -1)
        m2_PyErr_Msg(_dsa_err);
    m2_PyBuffer_Release(value, &vbuf);
    m2_PyBuffer_Release(r, &rbuf);
    m2_PyBuffer_Release(s, &sbuf);
    return ret;
}

PyObject *dsa_sign_asn1(DSA *dsa, PyObject *value) {
    void *sigbuf;
    Py_buffer vbuf;
    PyObject *ret;
    unsigned int siglen;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
        return NULL;

    if (!(sigbuf = PyMem_Malloc(DSA_size(dsa)))) {
        PyErr_SetString(PyExc_MemoryError, "dsa_sign_asn1");
        m2_PyBuffer_Release(value, &vbuf);
        return NULL;
    }
    if (!DSA_sign(0, vbuf.buf, vbuf.len,
                  (unsigned char *)sigbuf, &siglen, dsa)) {
        m2_PyErr_Msg(_dsa_err);
        PyMem_Free(sigbuf);
        m2_PyBuffer_Release(value, &vbuf);
        return NULL;
    }

    ret = PyBytes_FromStringAndSize(sigbuf, siglen);

    m2_PyBuffer_Release(value, &vbuf);
    PyMem_Free(sigbuf);
    return ret;
}

int dsa_verify_asn1(DSA *dsa, PyObject *value, PyObject *sig) {
    int ret;
    Py_buffer vbuf, sbuf;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
      return -1;
    if (m2_PyObject_GetBufferInt(sig, &sbuf, PyBUF_SIMPLE) == -1) {
      m2_PyBuffer_Release(value, &vbuf);
      return -1;
    }

    if ((ret = DSA_verify(0, (const void *) vbuf.buf, vbuf.len,
                          (void *) sbuf.buf, sbuf.len, dsa)) == -1)
        m2_PyErr_Msg(_dsa_err);
    m2_PyBuffer_Release(value, &vbuf);
    m2_PyBuffer_Release(sig, &sbuf);
    return ret;
}

int dsa_check_key(DSA *dsa) {
    const BIGNUM* pub_key, *priv_key;
    DSA_get0_key(dsa, &pub_key, &priv_key);
    return pub_key != NULL && priv_key != NULL;
}

int dsa_check_pub_key(DSA *dsa) {
    const BIGNUM* pub_key;
    DSA_get0_key(dsa, &pub_key, NULL);
    return pub_key ? 1 : 0;
}

int dsa_keylen(DSA *dsa) {
    const BIGNUM* p;
    DSA_get0_pqg(dsa, &p, NULL, NULL);
    return BN_num_bits(p);
}

int dsa_type_check(DSA *dsa) {
    return 1;
}
%}

