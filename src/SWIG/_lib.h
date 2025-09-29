/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

#include <openssl/bn.h>

static int m2_PyString_AsStringAndSizeInt(PyObject *obj, char **s, int *len);

static BIGNUM* m2_PyObject_AsBIGNUM(PyObject* value, PyObject* _py_exc) ;

/* Always use these two together, to correctly handle non-memoryview objects. */
static int m2_PyObject_GetBufferInt(PyObject *obj, Py_buffer *view, int flags);

int bn_gencb_callback(int p, int n, BN_GENCB *gencb);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);

