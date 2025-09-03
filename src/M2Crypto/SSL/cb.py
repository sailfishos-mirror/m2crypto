"""SSL callbacks

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import sys

from M2Crypto import X509, m2, types as C
from typing import List

__all__ = [
    "unknown_issuer",
    "ssl_verify_callback_stub",
    "ssl_verify_callback",
    "ssl_verify_callback_allow_unknown_ca",
    "ssl_info_callback",
]


def ssl_verify_callback_stub(ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok):
    # Deprecated
    return ok


unknown_issuer: List[int] = [
    m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    m2.X509_V_ERR_CERT_UNTRUSTED,
]


def ssl_verify_callback(
    ssl_ctx_ptr: C.SSL_CTX,
    x509_ptr: C.X509,
    errnum: int,
    errdepth: int,
    ok: int,
) -> int:
    from M2Crypto.SSL.Context import Context, ctxmap

    ssl_ctx = ctxmap()[id(ssl_ctx_ptr)]
    if errnum in unknown_issuer:
        if ssl_ctx.get_allow_unknown_ca():
            sys.stderr.write(
                "policy: %s: permitted...\n" % (m2.x509_get_verify_error(errnum))
            )
            sys.stderr.flush()
            ok = 1
    # CRL checking goes here...
    if ok:
        if ssl_ctx.get_verify_depth() >= errdepth:
            ok = 1
        else:
            ok = 0
    return ok


def ssl_verify_callback_allow_unknown_ca(
    ok: int, store: X509.X509_Store_Context
) -> int:
    """
    Callback that allows unknown CA errors.
    This version relies on a corrected SWIG typemap to receive a valid 'store' object.
    """
    store_ptr = store.ctx
    errnum = m2.x509_store_ctx_get_error(store_ptr)

    if errnum in unknown_issuer:
        # It's an error we want to ignore. Clear the error from the
        # context and return 1 to override the failure.
        m2.x509_store_ctx_set_error(store_ptr, m2.X509_V_OK)
        return 1

    # For any other error, respect the original verification status.
    return ok


# Cribbed from OpenSSL's apps/s_cb.c.
def ssl_info_callback(where: int, ret: int, ssl_ptr: C.SSL) -> None:
    where_int = where & ~m2.SSL_ST_MASK
    if where_int & m2.SSL_ST_CONNECT:
        state = "SSL connect"
    elif where_int & m2.SSL_ST_ACCEPT:
        state = "SSL accept"
    else:
        state = "SSL state unknown"

    if where & m2.SSL_CB_LOOP:
        sys.stderr.write("LOOP: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
        sys.stderr.flush()
        return

    if where & m2.SSL_CB_EXIT:
        if not ret:
            sys.stderr.write("FAILED: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
            sys.stderr.flush()
        else:
            sys.stderr.write("INFO: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
            sys.stderr.flush()
        return

    if where & m2.SSL_CB_ALERT:
        # Use a new variable for the alert operation string
        alert_op = "read" if (where & m2.SSL_CB_READ) else "write"
        sys.stderr.write(
            "ALERT: %s: %s: %s\n"
            % (
                alert_op,
                m2.ssl_get_alert_type_v(ret),
                m2.ssl_get_alert_desc_v(ret),
            )
        )
        sys.stderr.flush()
        return
