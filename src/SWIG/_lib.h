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

#if defined(__GNUC__) || defined(__clang__)
    // User-facing macros with string literals
    #define PRAGMA_PUSH_WARNINGS          _Pragma("GCC diagnostic push")
    #define PRAGMA_POP_WARNINGS           _Pragma("GCC diagnostic pop")
    #define PRAGMA_IGNORE_UNUSED_FUNCTION _Pragma("GCC diagnostic ignored \"-Wunused-function\"")
    #define PRAGMA_IGNORE_UNUSED_LABEL    _Pragma("GCC diagnostic ignored \"-Wunused-label\"")
    #define PRAGMA_WARN_STRICT_PROTOTYPES _Pragma("GCC diagnostic warning \"-Wstrict-prototypes\"")
#elif defined(_MSC_VER)
    #define PRAGMA_PUSH_WARNINGS          __pragma(warning(push))
    #define PRAGMA_POP_WARNINGS           __pragma(warning(pop))
    // C4505: unreferenced local function has been removed (closest to unused-function)
    #define PRAGMA_IGNORE_UNUSED_FUNCTION __pragma(warning(disable: 4505))
    // C4102: unreferenced label (equivalent to unused-label)
    #define PRAGMA_IGNORE_UNUSED_LABEL    __pragma(warning(disable: 4102))
    // C4255: no function prototype given (closest to strict-prototypes)
    // C4131: uses old-style declarator (also related to K&R style functions)
    #define PRAGMA_WARN_STRICT_PROTOTYPES __pragma(warning(default: 4255)) __pragma(warning(default: 4131))
#else
    // Fallback (No-op)
    #define PRAGMA_PUSH_WARNINGS
    #define PRAGMA_POP_WARNINGS
    #define PRAGMA_IGNORE_UNUSED_FUNCTION
    #define PRAGMA_IGNORE_UNUSED_LABEL
    #define PRAGMA_WARN_STRICT_PROTOTYPES
#endif
