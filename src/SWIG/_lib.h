/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

#include <openssl/bn.h>

#ifndef PY3K_COMPAT_H
#define PY3K_COMPAT_H

FILE* PyFile_AsFile(PyObject *p);
PyObject* PyFile_Name(PyObject *p);

#endif /* PY3K_COMPAT_H */

#ifndef PYTHON_LOGGING_H
#define PYTHON_LOGGING_H

#include <Python.h>

enum logtypes {info, warning, error, debug};

// Changed signature to support varargs (const char *format, ...)
static void log_msg(int type, const char *format, ...);

#endif /* PYTHON_LOGGING_H */

static int m2_PyString_AsStringAndSizeInt(PyObject *obj, char **s, int *len);

static BIGNUM* m2_PyObject_AsBIGNUM(PyObject* value, PyObject* _py_exc) ;

/* Always use these two together, to correctly handle non-memoryview objects. */
static int m2_PyObject_GetBufferInt(PyObject *obj, Py_buffer *view, int flags);

int bn_gencb_callback(int p, int n, BN_GENCB *gencb);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);
