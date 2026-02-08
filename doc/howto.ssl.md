---
orphan: true
---

(howto-ssl)=

# HOWTO: Programming SSL in Python with M2Crypto

```{eval-rst}

:author: Pheng Siong Ng <ngps@netmemetic.com> and Heikki Toivonen
    <heikki@osafoundation.org>
:copyright: © 2000, 2001 by Ng Pheng Siong,
            portions © 2006 by Open Source Applications Foundation
```

## Introduction

[M2Crypto](https://sr.ht/~mcepl/m2crypto/) is
a [Python](http://www.python.org) interface to
[OpenSSL](http://www.openssl.org). It makes available to the Python
programmer SSL functionality to implement clients and servers, S/MIME
v2, RSA, DSA, DH, symmetric ciphers, message digests and HMACs.

This document demonstrates programming HTTPS with M2Crypto.

## A bit of history

M2Crypto was created during the time of Python 1.5, which features a
module httplib providing client-side HTTP functionality. M2Crypto sports
a httpslib based on httplib.

Beginning with version 2.0, Python's socket module provided
(rudimentary) SSL support. Also in the same version, httplib was
enhanced with class HTTPConnection, which is more sophisticated than the
old class HTTP, and HTTPSConnection, which does HTTPS.

Subsequently, M2Crypto.httpslib grew a compatible (but not identical)
class HTTPSConnection.

The primary interface difference between the two HTTPSConnection classes
is that M2Crypto's version accepts an M2Crypto.SSL.Context instance as a
parameter, whereas Python 2.x's SSL support does not permit Pythonic
control of the SSL context.

Within the implementations, Python's `HTTPSConnection` employs a
`FakeSocket` object, which collects all input from the SSL connection
before returning it to the application as a `StringIO` buffer, whereas
M2Crypto's `HTTPSConnection` uses a buffering
`M2Crypto.BIO.IOBuffer` object that works over the underlying
M2Crypto.SSL.Connection directly.

Since then M2Crypto has gained a Twisted wrapper that allows securing
Twisted SSL connections with M2Crypto.

## Secure SSL

It is recommended that you read the book Network Security with OpenSSL
by John Viega, Matt Messier and Pravir Chandra, ISBN [059600270X].

Using M2Crypto does not automatically make an SSL connection secure.
There are various steps that need to be made before we can make that
claim. Let's see how a simple client can establish a secure
connection:

```
ctx = SSL.Context()
ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, depth=9)
if ctx.load_verify_locations('ca.pem') != 1: raise Exception('No CA certs')
s = SSL.Connection(ctx)
s.connect(server_address)
# Normal protocol (for example HTTP) commands follow
```

The first line creates an SSL context. The defaults allow any SSL
version (except SSL version 2 which has known weaknesses) and sets the
allowed ciphers to secure ones.

The second line tells M2Crypto to perform certificate validation. The
flags shown above are typical for clients, and requires the server to
send a certificate. The depth parameter tells how long certificate
chains are allowed - 9 is pretty common default, although probably too
long in practice.

The third line loads the allowed root (certificate authority or CA)
certificates. Most Linux distributions come with CA certificates in
suitable format. You could also download the
[certdata.txt](http://mxr.mozilla.org/seamonkey/source//security/nss/lib/ckfw/builtins/certdata.txt?raw=1)
file from the [NSS](http://www.mozilla.org/projects/security/pki/nss/)
project and convert it with the little M2Crypto utility script
[demo/x509/certdata2pem.py](http://svn.osafoundation.org/m2crypto/trunk/demo/x509/certdata2pem.py).

The fourth line creates an SSL connection object with the secure
context.

The fifth line connects to the server. During this time we perform the
last security step: just after connection, but before exchanging any
data, we compare the commonName (or subjectAltName DNS field) field in
the certificate the server returned to the server address we tried to
connect to. This happens automatically with SSL.Connection and the
Twisted wrapper class, and anything that uses those. In all other cases
you must do the check manually. It is recommended you call the
SSL.Checker to do the actual check.

SSL servers are different in that they typically do not require the
client to send a certificate, so there is usually no certificate
checking. Also, it is typically useless to perform host name checking.

## Code Samples

The best samples of how to use the various SSL objects are in the tests
directory, and the test_ssl.py file specifically. There are additional
samples in the demo directory, but they are not quaranteed to be up to
date.

NOTE: The tests and demos may not be secure as is. Use the information
above on how to make them secure.

## ssldump

ssldump "is an SSLv3/TLS network protocol analyser. It identifies TCP
connections on the chosen network interface and attempts to interpret
them as SSLv3/TLS traffic. When it identifies SSLv3/TLS traffic, it
decodes the records and displays them in a textual form to stdout. If
provided with the appropriate keying material, it will also decrypt the
connections and display the application data traffic.

If linked with OpenSSL, ssldump can display certificates in decoded form
and decrypt traffic (provided that it has the appropriate keying
material)."

ssldump is written by Eric Rescorla.

## HTTPS with PKCS#11 Engine Support

Here is an example of using a PKCS#11 engine with HTTPSConnection
(without proxy). This example demonstrates how to correctly load the
engine, certificate, and private key, and associate them with an SSL
Context.

```python
from M2Crypto import SSL, httpslib, m2, Engine

slot_id = "slot_00"

# 'loader' is the dynamic engine used to load the shared object
loader = Engine.load_dynamic_engine("pkcs11", "c:/tests_python/pkcs11.dll")

# 'pkcs11' is the actual engine instance we want to use
with Engine.Engine("pkcs11") as pkcs11:
    # Note: some PKCS#11 engines require MODULE_PATH to be set
    # before ENGINE_init(); engine behavior may vary.
    pkcs11.ctrl_cmd_string("MODULE_PATH",
                           "C:/WINDOWS/system32/OcsCryptoki.dll")

    # We do not call set_default(); the key and cert are bound
    # explicitly to the SSL context instead.

    # Load from the PKCS#11 engine, NOT the loader
    cert = pkcs11.load_certificate(slot_id)

    # PIN will be collected via the external engine’s UI
    # alternative is to use `pin=os.environ['PKCS11_PIN']`,
    # but the whole thing is highly engine-specific
    key = pkcs11.load_private_key(slot_id)

    ctx = SSL.Context('tls')

    # Use the loaded objects
    m2.ssl_ctx_use_x509(ctx.ctx, cert.x509)
    m2.ssl_ctx_use_pkey_privkey(ctx.ctx, key.pkey)

    ctx.set_verify(SSL.verify_none, depth=1)
    con = httpslib.HTTPSConnection('url', 443, ssl_context=ctx)
    con.request("GET", "/")
    resp = con.getresponse()
```

## HTTPS via Proxy with Engine Support

When using `ProxyHTTPSConnection` to tunnel HTTPS through a proxy, you
may need to use an OpenSSL Engine (e.g., for smartcards or HSMs). You
should configure an `SSL.Context` with the engine and pass it to the
connection.

Here is an example:

```python
from M2Crypto import Engine, SSL, httpslib, m2

# Load the dynamic engine and configure it to use the PKCS#11 module
Engine.load_dynamic()
with Engine.Engine('dynamic') as e:
    e.ctrl_cmd_string('SO_PATH', '/path/to/engine.so')
    e.ctrl_cmd_string('ID', 'pkcs11')
    e.ctrl_cmd_string('LIST_ADD', '1')
    e.ctrl_cmd_string('LOAD', None)
    e.ctrl_cmd_string('MODULE_PATH', '/path/to/pkcs11/module.so')

    # WARNING: this sets a *process-wide* OpenSSL default
    e.set_default(m2.ENGINE_METHOD_RSA)

    # Load the client certificate and private key from the smartcard
    # Certificate loading is engine-specific; many PKCS#11 engines
    # only expose private keys.
    cert = e.load_certificate('pkcs11:object=MyCert')
    # Fallback if the engine does not support certificate loading:
    # cert = X509.load_cert('client.pem')

    # PIN will be collected via the external engine’s UI
    # alternative is to use `pin=os.environ['PKCS11_PIN']`,
    # but the whole thing is highly engine-specific
    pkey = e.load_private_key('pkcs11:object=MyKey', pin=None)

    # Create an SSL context and configure it to use the client certificate
    ctx = SSL.Context('tls')
    ctx.load_verify_locations(capath='/etc/ssl/certs')
    ctx.set_verify(SSL.verify_peer, depth=9)
    ctx.load_cert_chain(cert, pkey)

    # Create a ProxyHTTPSConnection and use it to make a request
    # Ensure you do not call con.connect() manually if you use methods that trigger it (like request())
    con = httpslib.ProxyHTTPSConnection('proxy.example.com', 8080, ssl_context=ctx)
    # Absolute URL is required for proxy requests
    con.putrequest('GET', 'https://target.example.com/path')
    con.endheaders()

    # con.connect() is called implicitly by endheaders/send,
    # or you can call it manually if you haven't sent headers yet.
    # Do NOT call it twice.

    res = con.getresponse()
    print(res.read())
except EngineError as e:
    print("Engine failure:", e)
    raise
except SSL.SSLError as e:
    print("TLS failure:", e)
    raise
```

[059600270X]: https://meta.wikimedia.org/wiki/Special:BookSources/0321480910
