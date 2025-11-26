import socket
import threading
import time
import unittest

from M2Crypto import SSL

class TestServer(threading.Thread):
    def __init__(self, port, cert):
        threading.Thread.__init__(self)
        self.port = port
        self.cert = cert
        self.ready = threading.Event()
        self.daemon = True

    def run(self):
        ctx = SSL.Context()
        ctx.load_cert(self.cert)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', self.port))
        sock.listen(1)
        self.ready.set()

        client_sock, addr = sock.accept()

        try:
            client_sock.sendall(b"220 Hello\r\n")
            buf = client_sock.recv(1024)
            if not buf.startswith(b'EHLO'):
                return

            client_sock.sendall(b"250-Hello\r\n250 DSN\r\n250 STARTTLS\r\n")
            buf = client_sock.recv(1024)
            if not buf.startswith(b'STARTTLS'):
                return

            client_sock.sendall(b"220 Go ahead\r\n")

            conn = SSL.Connection(ctx, client_sock)
            conn.handshake_on_existing_socket(server_side=True)

            # Echo loop
            while True:
                try:
                    data = conn.read()
                    if not data:
                        break
                    if data.startswith(b'QUIT'):
                        conn.write(b'221 Bye\r\n')
                        break
                    conn.write(b"250 " + data)
                except SSL.SSLError:
                    break
        finally:
            client_sock.close()
            sock.close()

class StarttlsTest(unittest.TestCase):

    def setUp(self):
        self.cert = "tests/server.pem"
        self.port = 2526 #
        self.server = TestServer(self.port, self.cert)
        self.server.start()
        self.server.ready.wait(timeout=5)
        if not self.server.ready.is_set():
            self.fail("Server did not start")

    def tearDown(self):
        # The server thread will exit on its own
        pass

    def test_starttls_smtp(self):
        # Plain socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))

        # Plaintext communication
        resp = sock.recv(1024)
        self.assertTrue(resp.startswith(b"220"))

        sock.sendall(b"EHLO localhost\r\n")
        resp = sock.recv(1024)
        self.assertIn(b"STARTTLS", resp)

        sock.sendall(b"STARTTLS\r\n")
        resp = sock.recv(1024)
        self.assertTrue(resp.startswith(b"220"))

        # SSL handshake
        ctx = SSL.Context()
        conn = SSL.Connection(ctx, sock)
        ret = conn.handshake_on_existing_socket()
        self.assertEqual(ret, 1)

        # SSL communication
        conn.write(b"EHLO localhost\r\n")
        resp = conn.read()
        self.assertIn(b"250", resp)
        self.assertNotIn(b"STARTTLS", resp) # No STARTTLS after handshake

        conn.write(b"QUIT\r\n")
        resp = conn.read()
        self.assertTrue(resp.startswith(b"221"))

        conn.close()


if __name__ == "__main__":
    unittest.main()
