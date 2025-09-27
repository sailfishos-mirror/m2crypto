#ifndef PYTHON_LOGGING_H
#define PYTHON_LOGGING_H

#include <Python.h>

enum logtypes {info, warning, error, debug};

// Changed signature to support varargs (const char *format, ...)
static void log_msg(int type, const char *format, ...);

#endif /* PYTHON_LOGGING_H */
