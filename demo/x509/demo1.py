#!/usr/bin/env python

from __future__ import print_function

"""X.509 certificate manipulation and such.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import os

from M2Crypto import X509
from M2Crypto.EVP import MessageDigest

def demo1():
    print('Test 1: As DER...')
    cert1 = X509.load_cert('server.pem')
    der1 = cert1.as_der()
    dgst1 = MessageDigest('sha1')
    dgst1.update(der1)
    print('Using M2Crypto:\n', repr(dgst1.final()), '\n')

    cert2 = os.popen('openssl x509 -inform pem -outform der -in server.pem')
    der2 = cert2.read()
    dgst2 = MessageDigest('sha1')
    dgst2.update(der2)
    print('Openssl command line:\n', repr(dgst2.final()), '\n')


def demo2():
    print('Test 2: As text...')
    cert = X509.load_cert('client2.pem')
    print('version     ', cert.get_version())
    print('serial#     ', cert.get_serial_number())
    print('not before  ', cert.get_not_before())
    print('not after   ', cert.get_not_after())
    issuer = cert.get_issuer()
    #print('issuer      ', issuer)
    print('issuer.C    ', repr(issuer.C))
    print('issuer.SP   ', repr(issuer.SP))
    print('issuer.L    ', repr(issuer.L))
    print('issuer.O    ', repr(issuer.O))
    print('issuer.OU   ', repr(issuer.OU))
    print('issuer.CN   ', repr(issuer.CN))
    print('issuer.Email', repr(issuer.Email))
    print('subject     ', cert.get_subject())
    #print(cert.as_text(), '\n')

def demo3():
    cert = X509.load_cert('server.pem')
    while 1:
        x = cert.get_subject()

if __name__ == "__main__":
    #demo1()
    demo2()
    #demo3()
