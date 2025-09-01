"""SSL Exceptions

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

import socket

__all__ = ["SSLError", "SSLTimeoutError"]


class SSLError(Exception):
    pass


class SSLTimeoutError(SSLError, socket.timeout):
    pass
