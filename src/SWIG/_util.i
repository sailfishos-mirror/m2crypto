/* Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved.
 * Copyright (c) 2009-2010 Heikki Toivonen. All rights reserved.
*/
/* $Id$ */

%{
#include <openssl/x509v3.h>
%}

%warnfilter(454) _util_err;
%inline %{
static PyObject *_util_err;

void util_init(PyObject *util_err) {
    Py_INCREF(util_err);
    _util_err = util_err;
}

PyObject *util_hex_to_string(PyObject *blob) {
    PyObject *obj;
    char *ret;
    Py_buffer buf;

    if (m2_PyObject_GetBuffer(blob, &buf, PyBUF_SIMPLE) == -1)
        return NULL;

    ret = (char *)hex_to_string((unsigned char *)buf.buf, buf.len);
    if (!ret) {
        m2_PyErr_Msg(_util_err);
        m2_PyBuffer_Release(blob, &buf);
        return NULL;
    }

    obj = PyBytes_FromString(ret);

    OPENSSL_free(ret);
    m2_PyBuffer_Release(blob, &buf);
    return obj;
}

PyObject *util_string_to_hex(PyObject *blob) {
    PyObject *obj;
    unsigned char *ret;
    long len;
    Py_buffer buf;

    if (m2_PyObject_GetBuffer(blob, &buf, PyBUF_SIMPLE) == -1)
        return NULL;

    len = buf.len;
    ret = string_to_hex((char *)buf.buf, &len);
    if (ret == NULL) {
        m2_PyErr_Msg(_util_err);
        m2_PyBuffer_Release(blob, &buf);
        return NULL;
    }
    obj = PyBytes_FromStringAndSize((char*)ret, len);
    OPENSSL_free(ret);
    m2_PyBuffer_Release(blob, &buf);
    return obj;
}
%}
