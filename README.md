[![Documentation Status](https://readthedocs.org/projects/m2crypto/badge/?version=latest)](https://m2crypto.readthedocs.io/en/latest/)
[![SourceHut Mailing List](https://img.shields.io/badge/mailing%20list-~mcepl%2Fm2crypto-3065a2?logo=sourcehut&logoColor=white)](https://lists.sr.ht/~mcepl/m2crypto)
[![Support Channel](https://img.shields.io/badge/Matrix-%23m2crypto%3Aceplovi.cz-0DBD8B?logo=matrix&logoColor=white)](https://matrix.to/#/#m2crypto:ceplovi.cz)
![Issue Tracker](https://codefloe.com/mcepl/m2crypto/badges/issues.svg)

# [M2Crypto]

## M2Crypto = Python + OpenSSL + SWIG

![Build Status](https://codefloe.com/mcepl/m2crypto/badges/workflows/main.yml/badge.svg)

**NOTE: This library is currently in maintenance mode (and it has been
in it since 2014 and I don’t plan to stop maintaining it anytime soon).
For new applications we recommend using a more modern alternative such
as** [PyCA/cryptography]. **Examples of how to migrate can be found in**
[the documentation].

M2Crypto is a crypto and SSL toolkit for Python.

M2 stands for "me, too!"

M2Crypto comes with the following:

- **RSA**, **DSA**, **DH**, **HMACs**, **message digests**,
  **symmetric ciphers** including **AES**,
- **TLS** functionality to implement **clients and servers**.
- **Example SSL client and server programs**, which are variously
  **threading**, **forking** or based on **non-blocking socket IO**.
- **HTTPS** extensions to Python's **httplib, urllib and xmlrpclib**.
- Unforgeable HMAC'ing **AuthCookies** for **web session management**.
- **FTP/TLS** client and server.
- **S/MIME v2**.
- **ZSmime**: An S/MIME messenger for **Zope**.

We care a lot about stable API and all Python methods should be
preserved, note however that `m2.` namespace is considered internal to
the library and it doesn't have to be preserved. If however some change
to it breaks your app, let us know and we will try to make things
working for you.

M2Crypto is released under a very liberal BSD-2-Clause licence. See
LICENSES/BSD-2-Clause.txt for details.

To install, see the file [INSTALL].

Look at the tests and demos for example use. Recommended reading before
deploying in production is "Network Security with OpenSSL" by John Viega,
Matt Messier and Pravir Chandra, ISBN [059600270X].

Note these caveats:

- Possible memory leaks, because some objects need to be freed on the
  Python side and other objects on the C side, and these may change
  between OpenSSL versions. (Multiple free's lead to crashes very
  quickly, so these should be relatively rare.)
- No memory locking/clearing for keys, passphrases, etc. because AFAIK
  Python does not provide the features needed. On the C (OpenSSL) side
  things are cleared when the Python objects are deleted.

Have fun! Your feedback is welcome.

[M2Crypto]: https://codefloe.com/mcepl/m2crypto
[the documentation]: https://m2crypto.readthedocs.io/en/latest/
[pyca/cryptography]: https://cryptography.io/en/latest/
[INSTALL]: ./src/branch/master/INSTALL.md
[059600270X]: https://meta.wikimedia.org/wiki/Special:BookSources/0321480910
