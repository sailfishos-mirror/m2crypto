%{

/***********************************************************/
/* define logging function and logtypes for python.logging */
/* by H.Dickten 2014                                      */
/* https://gist.github.com/hensing/0db3f8e3a99590006368   */
/***********************************************************/

#include <stdarg.h> // Include for va_list

// Buffer size for formatted log message
#define LOG_MSG_MAX_SIZE 512

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void log_msg(int type, const char *format, ...)
{
    static PyObject *logging = NULL;
    char buffer[LOG_MSG_MAX_SIZE];
    va_list args;
    PyObject *string = NULL;

    // Format the message
    va_start(args, format);
    vsnprintf(buffer, LOG_MSG_MAX_SIZE, format, args);
    va_end(args);

    // import logging module on demand
    if (logging == NULL){
        // Using "logging" module name directly, no need to check NoBlock
        logging = PyImport_ImportModule("logging");
        if (logging == NULL) {
            // Error importing module is handled by PyErr_Occurred() later
            return;
        }
    }

    // build msg-string from the formatted buffer
    string = Py_BuildValue("s", buffer);
    if (string == NULL) {
        // Handle error building string
        return;
    }

    // call function depending on loglevel
    switch (type)
    {
        case info:
            PyObject_CallMethod(logging, "info", "O", string);
            break;

        case warning:
            PyObject_CallMethod(logging, "warn", "O", string);
            break;

        case error:
            PyObject_CallMethod(logging, "error", "O", string);
            break;

        case debug:
            PyObject_CallMethod(logging, "debug", "O", string);
            break;
    }
    Py_DECREF(string);
    // Clear any temporary Python error set by PyObject_CallMethod if logging failed
    // (A failed log call should not propagate to the C caller)
    if (PyErr_Occurred()) {
        PyErr_Clear();
    }
}
#pragma GCC diagnostic pop
%}
