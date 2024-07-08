import logging
import platform
import struct
import sys

try:
    import unittest2 as unittest
except ImportError:
    import unittest
__oldStartTestRun = unittest.result.TestResult.startTestRun
__oldStopTestRun = unittest.result.TestResult.stopTestRun

logging.basicConfig(
    format='%(levelname)s:%(funcName)s:%(message)s',
    stream=sys.stdout,
    level=logging.DEBUG,
)

report_leaks = False


logging.basicConfig(
    format="%(levelname)s:%(funcName)s:%(message)s",
    level=logging.DEBUG,
)

def __dump_garbage():
    import gc

    print('\nGarbage:')
    gc.collect()
    if len(gc.garbage):

        print('\nLeaked objects:')
        for x in gc.garbage:
            s = str(x)
            if len(s) > 77:
                s = s[:73] + '...'
            print(type(x), '\n  ', s)

        print('There were %d leaks.' % len(gc.garbage))
    else:
        print('Python garbage collector did not detect any leaks.')
        print(
            'However, it is still possible there are leaks in the C code.'
        )


def startTestRun(self):
    from M2Crypto import m2

    print(
        'Version of OpenSSL is {0:x} ({1:s})'.format(
            m2.OPENSSL_VERSION_NUMBER, m2.OPENSSL_VERSION_TEXT
        )
    )
    print(
        '(struct.calcsize("P") * 8) == 32 : {}'.format(
            (struct.calcsize("P") * 8) == 32
        )
    )
    print(
        "not(sys.maxsize > 2**32) : {}".format(
            not (sys.maxsize > 2**32)
        )
    )
    print("libc_ver = {}".format(platform.libc_ver()))
    sys.stderr.flush()
    sys.stdout.flush()

    if report_leaks:
        import gc

        gc.enable()
        gc.set_debug(gc.DEBUG_LEAK & ~gc.DEBUG_SAVEALL)

    __oldStartTestRun(self)


def stopTestRun(self):
    if report_leaks:
        from tests import __dump_garbage

        __dump_garbage()

    __oldStopTestRun(self)


unittest.result.TestResult.startTestRun = startTestRun
unittest.result.TestResult.stopTestRun = stopTestRun
