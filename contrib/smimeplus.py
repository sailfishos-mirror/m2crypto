import UserDict
import os
import tempfile

from M2Crypto import BIO, Rand, SMIME, X509

from email import Message


class smimeplus(object):
    def __init__(self, cert, privkey, passphrase, cacert, randfile=None):
        self.cipher = "aes_256_cbc"  # XXX make it configable??
        self.setsender(cert, privkey, passphrase)
        self.setcacert(cacert)

        if randfile is None and os.path.exists("/dev/urandom"):
            # Default to /dev/urandom on POSIX-like systems if no file is specified
            self.randfile = "/dev/urandom"
        else:
            self.randfile = randfile
        self.__loadrand()

    def __passcallback(self, v):
        """private key passphrase callback function"""
        return self.passphrase

    def __loadrand(self):
        """Load random number file"""
        if self.randfile:
            # On POSIX-like systems, only load a small amount from /dev/urandom
            # to seed the PRNG, unless it's a dedicated file for state saving.
            if self.randfile == "/dev/urandom":
                # Read -1 bytes (all available), M2Crypto Rand.load_file() reads up to 1024 bytes
                # from /dev/urandom by default if max_bytes is -1 (or similar logic).
                # To be explicit, we can load a small seed.
                Rand.load_file(self.randfile, 1024)
            else:
                # Load the full user-specified random file
                Rand.load_file(self.randfile, -1)

    def __saverand(self):
        """Save random number file"""
        if self.randfile and self.randfile != "/dev/urandom":
            Rand.save_file(self.randfile)

    def __gettext(self, msg):
        """Return a string representation of 'msg'"""
        _data = ""
        if isinstance(msg, Message.Message):
            for _p in msg.walk():
                _data = _data + _p.as_string()
        else:
            _data = str(msg)
        return _data

    def __pack(self, msg):
        """Convert 'msg' to string and put it into an memory buffer for
        openssl operation"""
        return BIO.MemoryBuffer(self.__gettext(msg))

    def setsender(self, cert=None, privkey=None, passphrase=None):
        if cert:
            self.cert = cert
        if privkey:
            self.key = privkey
        if passphrase:
            self.passphrase = passphrase

    def setcacert(self, cacert):
        self.cacert = cacert

    def sign(self, msg):
        """Sign a message"""
        _sender = SMIME.SMIME()
        _sender.load_key_bio(
            self.__pack(self.key),
            self.__pack(self.cert),
            callback=self.__passcallback,
        )

        _signed = _sender.sign(self.__pack(msg), SMIME.PKCS7_DETACHED)

        _out = self.__pack(None)
        _sender.write(_out, _signed, self.__pack(msg))
        return _out.read()

    def verify(self, smsg, scert):
        """Verify to see if 'smsg' was signed by 'scert', and scert was
        issued by cacert of this object.  Return message signed if success,
        None otherwise"""
        # Load signer's cert.
        _x509 = X509.load_cert_bio(self.__pack(scert))
        _stack = X509.X509_Stack()
        _stack.push(_x509)

        # Load CA cert directly from the data into a BIO and then the X509_Store.
        _ca_bio = self.__pack(self.cacert)
        _store = X509.X509_Store()
        # load_info_bio is the typical replacement for file-based loading with a BIO.
        _store.load_info_bio(_ca_bio)

        # prepare SMIME object
        _sender = SMIME.SMIME()
        _sender.set_x509_stack(_stack)
        _sender.set_x509_store(_store)

        # Load signed message, verify it, and return result
        _p7, _data = SMIME.smime_load_pkcs7_bio(self.__pack(smsg))
        try:
            # Removed flags=SMIME.PKCS7_SIGNED which erroneously sets PKCS7_NOSIGS
            # https://todo.sr.ht/~mcepl/m2crypto/329
            return _sender.verify(
                _p7, _data, flags=0  # Use flags=0 for standard verification
            )
        except SMIME.SMIME_Error:
            return None

    def encrypt(self, rcert, msg):
        # Instantiate an SMIME object.
        _sender = SMIME.SMIME()

        # Load target cert to encrypt to.
        _x509 = X509.load_cert_bio(self.__pack(rcert))
        _stack = X509.X509_Stack()
        _stack.push(_x509)
        _sender.set_x509_stack(_stack)

        _sender.set_cipher(SMIME.Cipher(self.cipher))

        # Encrypt the buffer.
        _buf = self.__pack(self.__gettext(msg))
        _p7 = _sender.encrypt(_buf)

        # Output p7 in mail-friendly format.
        _out = self.__pack("")
        _sender.write(_out, _p7)

        # Save the PRNG's state.
        self.__saverand()

        return _out.read()

    def decrypt(self, emsg):
        """decrypt 'msg'.  Return decrypt message if success, None
        otherwise"""
        # Load private key and cert.
        _sender = SMIME.SMIME()
        _sender.load_key_bio(
            self.__pack(self.key),
            self.__pack(self.cert),
            callback=self.__passcallback,
        )

        # Load the encrypted data.
        _p7, _data = SMIME.smime_load_pkcs7_bio(self.__pack(emsg))

        # Decrypt p7.
        try:
            return _sender.decrypt(_p7)
        except SMIME.SMIME_Error:
            return None

    def addHeader(self, rcert, content, subject=""):
        """Add To, From, Subject Header to 'content'"""
        _scert = X509.load_cert_bio(self.__pack(self.cert))
        # Use get_components() to get CN and emailAddress
        _scertsubj_data = _scert.get_subject().get_components()

        _rcert = X509.load_cert_bio(self.__pack(rcert))
        # Use get_components() to get CN and emailAddress directly
        _rcertsubj_data = _rcert.get_subject().get_components()

        # The data comes from get_components, which returns bytes, so decode them.
        _sender_cn = _scertsubj_data.get("CN", b"").decode()
        _sender_email = _scertsubj_data.get("emailAddress", b"").decode()
        _recipient_cn = _rcertsubj_data.get("CN", b"").decode()
        _recipient_email = _rcertsubj_data.get("emailAddress", b"").decode()

        _out = f'From: "{_sender_cn}" <{_sender_email}>\n'
        _out += f'To: "{_recipient_cn}" <{_recipient_email}>\n'
        _out += f"Subject: {subject}\n"
        _out += content

        return _out
