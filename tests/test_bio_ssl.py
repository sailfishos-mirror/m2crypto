#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import socket
import threading

from M2Crypto import BIO
from M2Crypto import SSL
from M2Crypto import Err
from M2Crypto import Rand
from M2Crypto import threading as m2threading

from tests import unittest
from tests.test_ssl import srv_host, allocate_srv_port

# Timeout (seconds) for blocking socket operations in the handshake test.
# Prevents the test from hanging indefinitely if the handshake deadlocks.
_HANDSHAKE_TIMEOUT = 10


class HandshakeClient(threading.Thread):

    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.error = None

    def run(self):
        ctx = SSL.Context()
        ctx.load_cert_chain("tests/server.pem")
        conn = SSL.Connection(ctx)
        cipher_list = conn.get_cipher_list()
        sslbio = BIO.SSLBio()
        readbio = BIO.MemoryBuffer()
        writebio = BIO.MemoryBuffer()
        sslbio.set_ssl(conn)
        conn.set_bio(readbio, writebio)
        conn.set_connect_state()
        sock = socket.socket()
        sock.settimeout(_HANDSHAKE_TIMEOUT)
        sock.connect((self.host, self.port))

        handshake_complete = False
        while not handshake_complete:
            ret = sslbio.do_handshake()
            if ret <= 0:
                if not sslbio.should_retry():
                    err_string = Err.get_error()
                    print(err_string)
                    self.error = "unrecoverable error in handshake - client"
                    sock.close()
                    return
                # Always flush any pending output before deciding to read.
                output_token = writebio.read()
                if output_token is not None:
                    sock.sendall(output_token)
                elif sslbio.should_read():
                    input_token = sock.recv(1024)
                    if not input_token:
                        self.error = "connection closed during handshake - client"
                        sock.close()
                        return
                    readbio.write(input_token)
            else:
                handshake_complete = True

        output_token = writebio.read()
        if output_token is not None:
            sock.sendall(output_token)
        sock.close()


class SSLTestCase(unittest.TestCase):

    def setUp(self):
        self.sslbio = BIO.SSLBio()

    def test_pass(self):  # XXX leaks 64/24 bytes
        pass

    def test_set_ssl(self):  # XXX leaks 64/1312 bytes
        ctx = SSL.Context()
        conn = SSL.Connection(ctx)
        self.sslbio.set_ssl(conn)

    def test_do_handshake_fail(self):  # XXX leaks 64/42066 bytes
        ctx = SSL.Context()
        conn = SSL.Connection(ctx)
        conn.set_connect_state()
        self.sslbio.set_ssl(conn)
        ret = self.sslbio.do_handshake()
        self.assertIn(ret, (-1, 0))

    def test_should_retry_fail(self):  # XXX leaks 64/1312 bytes
        ctx = SSL.Context()
        conn = SSL.Connection(ctx)
        self.sslbio.set_ssl(conn)
        ret = self.sslbio.do_handshake()
        self.assertIn(ret, (-1, 0))
        ret = self.sslbio.should_retry()
        self.assertEqual(ret, 0)

    def test_should_write_fail(self):  # XXX leaks 64/1312 bytes
        ctx = SSL.Context()
        conn = SSL.Connection(ctx)
        self.sslbio.set_ssl(conn)
        ret = self.sslbio.do_handshake()
        self.assertIn(ret, (-1, 0))
        ret = self.sslbio.should_write()
        self.assertEqual(ret, 0)

    def test_should_read_fail(self):  # XXX leaks 64/1312 bytes
        ctx = SSL.Context()
        conn = SSL.Connection(ctx)
        self.sslbio.set_ssl(conn)
        ret = self.sslbio.do_handshake()
        self.assertIn(ret, (-1, 0))
        ret = self.sslbio.should_read()
        self.assertEqual(ret, 0)

    def test_do_handshake_succeed(self):  # XXX leaks 196/26586 bytes
        ctx = SSL.Context()
        ctx.load_cert_chain("tests/server.pem")
        conn = SSL.Connection(ctx)
        self.sslbio.set_ssl(conn)
        readbio = BIO.MemoryBuffer()
        writebio = BIO.MemoryBuffer()
        conn.set_bio(readbio, writebio)
        conn.set_accept_state()
        handshake_complete = False
        srv_port = allocate_srv_port()
        sock = socket.socket()
        sock.bind((srv_host, srv_port))
        sock.listen(5)
        handshake_client = HandshakeClient(srv_host, srv_port)
        handshake_client.start()
        new_sock, _ = sock.accept()
        new_sock.settimeout(_HANDSHAKE_TIMEOUT)
        while not handshake_complete:
            input_token = new_sock.recv(1024)
            if not input_token:
                self.fail("connection closed during handshake - server")
            readbio.write(input_token)

            ret = self.sslbio.do_handshake()
            if ret <= 0:
                if not self.sslbio.should_retry() or not self.sslbio.should_read():
                    self.fail("unrecoverable error in handshake - server")
            else:
                handshake_complete = True

            output_token = writebio.read()
            if output_token is not None:
                new_sock.sendall(output_token)

        handshake_client.join()
        if handshake_client.error is not None:
            self.fail(handshake_client.error)
        sock.close()
        new_sock.close()


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(SSLTestCase)


if __name__ == "__main__":
    Rand.load_file("randpool.dat", -1)
    m2threading.init()
    unittest.TextTestRunner().run(suite())
    m2threading.cleanup()
    Rand.save_file("randpool.dat")
