"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

import binascii
import logging

from M2Crypto import ASN1, BIO, EVP, m2, types as C
from typing import (
    Callable,
    List,
    Optional,
    Union,
    Iterator,
    Any,
    overload,
    Iterable,
)

FORMAT_DER = 0
FORMAT_PEM = 1

__g = globals()
for x in dir(m2):
    if x.startswith("X509_V_ERR"):
        __g[x] = getattr(m2, x)
    elif x.startswith("XN_FLAG_"):
        __g[x] = getattr(m2, x)
    elif x.startswith("X509_PURPOSE_"):
        __g[x] = getattr(m2, x)
    elif x.startswith("VERIFY_"):
        __g[x.lower()] = getattr(m2, x)

log = logging.getLogger(__name__)


class X509Error(ValueError):
    pass


m2.x509_init(X509Error)

V_OK: int = m2.X509_V_OK


class X509_Extension(object):
    """
    X509 Extension
    """

    def __init__(
        self, x509_ext_ptr: Optional[C.X509_EXTENSION] = None, _pyfree: int = 1
    ) -> None:
        self.x509_ext = x509_ext_ptr
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0) and self.x509_ext:
            m2.x509_extension_free(self.x509_ext)

    def _ptr(self) -> Optional[C.X509_EXTENSION]:
        return self.x509_ext

    def set_critical(self, critical: int = 1) -> int:
        """
        Mark this extension critical or noncritical. By default an
        extension is not critical.

        :param critical: Nonzero sets this extension as critical.
                         Calling this method without arguments will
                         set this extension to critical.
        :return: 1 for success, 0 for failure
        """
        if self.x509_ext is None:
            raise X509Error("Extension not initialized")
        return m2.x509_extension_set_critical(self.x509_ext, critical)

    def get_critical(self) -> int:
        """
        Return whether or not this is a critical extension.

        :return:  Nonzero if this is a critical extension.
        """
        if self.x509_ext is None:
            raise X509Error("Extension not initialized")
        return m2.x509_extension_get_critical(self.x509_ext)

    def get_name(self) -> str:
        """
        Get the extension name, for example 'subjectAltName'.
        """
        if self.x509_ext is None:
            raise X509Error("Extension not initialized")
        out = m2.x509_extension_get_name(self.x509_ext)
        return out.decode()

    def get_value(self, flag: int = 0, indent: int = 0) -> str:
        """
        Get the extension value, for example 'DNS:www.example.com'.

        :param flag:   Flag to control what and how to print.
        :param indent: How many spaces to print before actual value.
        """
        if self.x509_ext is None:
            raise X509Error("Extension not initialized")
        buf = BIO.MemoryBuffer()
        m2.x509_ext_print(buf.bio_ptr(), self.x509_ext, flag, indent)
        return (buf.read_all() or b"").decode()


def new_extension(
    name: str,
    value: str,
    critical: int = 0,
    _pyfree: int = 1,
    pkey: Optional[EVP.PKey] = None,
) -> X509_Extension:
    """
    Create a new X509_Extension instance using OpenSSL's internal V3 extension configuration.

    This method relies on the OpenSSL 'x509v3_ext_conf' function to parse a
    textual extension name and value into an X509_EXTENSION structure.

    :param name: The short name of the extension (e.g.,
                 'subjectAltName', 'basicConstraints').
    :param value: The value string for the extension (e.g.,
                  'DNS:example.com', 'CA:TRUE'). For complex
                  extensions like 'subjectKeyIdentifier', the
                  value often specifies the content, such as
                  'hash' to compute the hash of the subject's
                  public key.
    :param critical: Set to 1 to mark the extension as critical,
                  0 otherwise (default is 0).
    :param _pyfree: Internal flag (default 1).
    :param pkey: Optional EVP.PKey object. **Required** when the
                 extension value requires an associated public
                 key to be computed, such as when: - `name` is
                 'subjectKeyIdentifier' and `value` is 'hash'. If
                 an extension requires a public key context and
                 `pkey` is None, an `X509Error` will be raised to
                 prevent a Segmentation Fault (SIGSEGV) in modern
                 OpenSSL versions by accessing an uninitialized
                 context pointer.

    :return: A new `X509_Extension` instance.
    :raises X509Error: If the extension cannot be created (e.g.,
                 invalid name/value) or if a required context
                 (`pkey`) is missing.
    """
    ctx = m2.x509v3_set_nconf()

    # This block enforces context availability for subjectKeyIdentifier:hash
    # to prevent a SIGSEGV in OpenSSL > 3.0 when ctx->subject_cert is NULL.
    if name == "subjectKeyIdentifier" and value == "hash" and pkey is None:
        m2.x509v3_ctx_free(ctx)  # Clean up the context object before raising error
        raise X509Error(
            "Cannot create 'subjectKeyIdentifier:hash' without a public key (pkey) context."
        )

    if pkey is not None:
        m2.X509V3_CTX_set_nconf_pkey(ctx, pkey._ptr())
    x509_ext_ptr = m2.x509v3_ext_conf(None, ctx, name, str(value))
    if x509_ext_ptr is None:
        raise X509Error(
            "Cannot create X509_Extension with name '%s' and value '%s'" % (name, value)
        )
    x509_ext = X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext


class X509_Extension_Stack(object):
    """
    X509 Extension Stack

    :warning: Do not modify the underlying OpenSSL stack
              except through this interface, or use any OpenSSL
              functions that do so indirectly. Doing so will get the
              OpenSSL stack and the internal pystack of this class out
              of sync, leading to python memory leaks, exceptions or
              even python crashes!
    """

    def __init__(
        self, stack: Optional[C.STACK_OF_X509_EXTENSION] = None, _pyfree: int = 0
    ) -> None:
        self.pystack: List[X509_Extension] = []
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            num = m2.sk_x509_extension_num(self.stack)
            for i in range(num):
                # Set _pyfree=0, the C stack owns the extension objects.
                self.pystack.append(
                    X509_Extension(
                        m2.sk_x509_extension_value(self.stack, i),
                        _pyfree=0,
                    )
                )
        else:
            self.stack = m2.sk_x509_extension_new_null()
            self._pyfree = 1

    def __del__(self) -> None:
        # see BIO.py - unbalanced __init__ / __del__
        if getattr(self, "_pyfree", 0):
            m2.sk_x509_extension_free(self.stack)

    def __len__(self) -> int:
        return len(self.pystack)

    def __getitem__(self, idx: int) -> X509_Extension:
        return self.pystack[idx]

    def __iter__(self) -> Iterator[X509_Extension]:
        return iter(self.pystack)

    def _ptr(self) -> C.STACK_OF_X509_EXTENSION:
        return self.stack

    def push(self, x509_ext: X509_Extension) -> int:
        """
        Push X509_Extension object onto the stack.

        :param x509_ext: X509_Extension object to be pushed onto the stack.
        :return: The number of extensions on the stack.
        """
        ext_ptr = x509_ext._ptr()
        if ext_ptr is None:
            raise X509Error("Cannot push an uninitialized extension")
        self.pystack.append(x509_ext)
        ret = m2.sk_x509_extension_push(self.stack, ext_ptr)
        assert ret == len(self.pystack)
        return ret

    def pop(self) -> Optional[X509_Extension]:
        """
        Pop X509_Extension object from the stack.

        :return: X509_Extension object that was popped, or None if there is
                 nothing to pop.
        """
        x509_ext_ptr = m2.sk_x509_extension_pop(self.stack)
        if x509_ext_ptr is None:
            assert len(self.pystack) == 0
            return None
        return self.pystack.pop()


class X509_Name_Entry(object):
    """
    X509 Name Entry
    """

    def __init__(self, x509_name_entry: C.X509_NAME_ENTRY, _pyfree: int = 0) -> None:
        """
        :param x509_name_entry: this should be OpenSSL X509_NAME_ENTRY binary
        :param _pyfree:
        """
        self.x509_name_entry = x509_name_entry
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_name_entry_free(self.x509_name_entry)

    def _ptr(self) -> C.X509_NAME_ENTRY:
        return self.x509_name_entry

    def set_object(self, asn1obj: ASN1.ASN1_Object) -> int:
        """
        Sets the field name to asn1obj

        :param asn1obj:
        :return: 0 on failure, 1 on success
        """
        return m2.x509_name_entry_set_object(self.x509_name_entry, asn1obj._ptr())

    def set_data(self, data: bytes, type: int = ASN1.MBSTRING_ASC) -> int:
        """
        Sets the field value.

        :param data: data in a binary form to be set
        :return: 0 on failure, 1 on success
        """
        return m2.x509_name_entry_set_data(self.x509_name_entry, type, data)

    def get_object(self) -> ASN1.ASN1_Object:
        obj_ptr = m2.x509_name_entry_get_object(self.x509_name_entry)
        return ASN1.ASN1_Object(obj_ptr, _pyfree=0)

    def get_data(self) -> ASN1.ASN1_String:
        str_ptr = m2.x509_name_entry_get_data(self.x509_name_entry)
        return ASN1.ASN1_String(str_ptr, _pyfree=0)

    def create_by_txt(
        self, field: str, type: int, entry: bytes, length: int
    ) -> C.X509_NAME_ENTRY:
        """
        Creates and returns a new X509_NAME_ENTRY object.
        Note: This is a factory method that uses an existing instance's
        pointer space in a confusing way. It should likely be a static or
        class method for clarity. The corrected implementation below makes it work
        as written.
        """
        return m2.x509_name_entry_create_by_txt(
            self.x509_name_entry, field, type, entry, length
        )


class X509_Name(object):
    """
    X509 Name
    """

    nid = {
        "C": m2.NID_countryName,
        "SP": m2.NID_stateOrProvinceName,
        "ST": m2.NID_stateOrProvinceName,
        "stateOrProvinceName": m2.NID_stateOrProvinceName,
        "L": m2.NID_localityName,
        "localityName": m2.NID_localityName,
        "O": m2.NID_organizationName,
        "organizationName": m2.NID_organizationName,
        "OU": m2.NID_organizationalUnitName,
        "organizationUnitName": m2.NID_organizationalUnitName,
        "CN": m2.NID_commonName,
        "commonName": m2.NID_commonName,
        "Email": m2.NID_pkcs9_emailAddress,
        "emailAddress": m2.NID_pkcs9_emailAddress,
        "serialNumber": m2.NID_serialNumber,
        "SN": m2.NID_surname,
        "surname": m2.NID_surname,
        "GN": m2.NID_givenName,
        "givenName": m2.NID_givenName,
    }

    _alias_map = {
        "SP": "ST",
        "Email": "emailAddress",
    }

    def __init__(
        self, x509_name: Optional[C.X509_NAME] = None, _pyfree: int = 0
    ) -> None:
        """
        :param x509_name: this should be OpenSSL X509_NAME binary
        :param _pyfree:
        """
        if x509_name is not None:
            assert m2.x509_name_type_check(x509_name), "'x509_name' type error"
            self.x509_name = x509_name
            self._pyfree = _pyfree
        else:
            self.x509_name = m2.x509_name_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_name_free(self.x509_name)

    def __str__(self) -> str:
        return m2.x509_name_oneline(self.x509_name)

    def __getattr__(self, attr: str) -> str:
        if attr in self.nid:
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
            out = m2.x509_name_by_nid(self.x509_name, self.nid[attr])
            if out is None:
                raise AttributeError(attr)
            return out.decode()
        raise AttributeError(attr)

    def __setattr__(self, attr: str, value: Any) -> None:
        """
        :return: 1 for success of 0 if an error occurred.
        """
        if attr in self.nid:
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
            self.add_entry_by_txt(attr, ASN1.MBSTRING_ASC, value, -1, -1, 0)
        else:
            super().__setattr__(attr, value)

    def __len__(self) -> int:
        return m2.x509_name_entry_count(self.x509_name)

    def __getitem__(self, idx: int) -> X509_Name_Entry:
        if not 0 <= idx < len(self):
            raise IndexError("index out of range")
        return X509_Name_Entry(m2.x509_name_get_entry(self.x509_name, idx), _pyfree=0)

    def __iter__(self) -> Iterator[X509_Name_Entry]:
        for i in range(len(self)):
            yield self[i]

    def _ptr(self) -> C.X509_NAME:
        return self.x509_name

    def add_entry_by_txt(
        self,
        field: str,
        type: int,
        entry: Union[str, bytes],
        len: int,
        loc: int,
        set: int,
    ) -> int:
        """
        Add X509_Name field whose name is identified by its name.

        :param field: name of the entry
        :param type: use MBSTRING_ASC or MBSTRING_UTF8
               (or standard ASN1 type like V_ASN1_IA5STRING)
        :param entry: value
        :param len: buf_len of the entry
               (-1 and the length is computed automagically)
        :param loc: determines the index where the new entry is
               inserted: if it is -1 it is appended.
        :param set: determines how the new type is added. If it is zero
               a new RDN is created.
               If set is -1 or 1 it is added to the previous or next RDN
               structure respectively. This will then be a multivalued
               RDN: since multivalues RDNs are very seldom used set is
               almost always set to zero.

        :return: 1 for success of 0 if an error occurred.
        """
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"

        # The SWIG wrapper for this function is quirky and appears to expect
        # Python strings for both field and entry, handling encoding internally.
        entry_str = entry.decode("utf-8") if isinstance(entry, bytes) else str(entry)

        canonical_field = self._alias_map.get(field, field)

        ret = m2.x509_name_add_entry_by_txt(
            self.x509_name, canonical_field, type, entry_str, len, loc, set
        )
        if not ret:
            err_code = m2.err_get_error()
            m2.err_clear_error()
            err_lib = m2.err_lib_error_string(err_code)
            err_func = m2.err_func_error_string(err_code)
            err_reason = m2.err_reason_error_string(err_code)
            raise X509Error(
                "Failed to set attribute '{}'. OpenSSL error: [{}] {}: {}".format(
                    field, err_lib, err_func, err_reason
                )
            )
        return ret

    def entry_count(self) -> int:
        return m2.x509_name_entry_count(self.x509_name)

    def get_entries_by_nid(self, nid: int) -> List[X509_Name_Entry]:
        """
        Retrieve the next index matching nid.

        :param nid: name of the entry (as m2.NID* constants)

        :return: list of X509_Name_Entry items
        """
        ret = []
        lastpos = -1

        while True:
            lastpos = m2.x509_name_get_index_by_nid(self.x509_name, nid, lastpos)
            if lastpos == -1:
                break

            ret.append(self[lastpos])

        return ret

    def as_text(self, indent: int = 0, flags: int = m2.XN_FLAG_COMPAT) -> str:
        """
        as_text returns the name as a string.

        :param indent: Each line in multiline format is indented
                       by this many spaces.
        :param flags:  Flags that control how the output should be formatted.
        """
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        buf = BIO.MemoryBuffer()
        m2.x509_name_print_ex(buf.bio_ptr(), self.x509_name, indent, flags)
        return (buf.read_all() or b"").decode()

    def as_der(self) -> bytes:
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        return m2.x509_name_get_der(self.x509_name)

    def as_hash(self) -> int:
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        return m2.x509_name_hash(self.x509_name)


class X509(object):
    """
    X.509 Certificate
    """

    def __init__(self, x509: Optional[C.X509] = None, _pyfree: int = 0) -> None:
        """
        :param x509: binary representation of
               the underlying OpenSSL X509 object.
        """
        if x509 is not None:
            assert m2.x509_type_check(x509), "'x509' type error"
            self.x509 = x509
            self._pyfree = _pyfree
        else:
            self.x509 = m2.x509_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_free(self.x509)

    def _ptr(self) -> C.X509:
        return self.x509

    def as_text(self) -> str:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf = BIO.MemoryBuffer()
        m2.x509_print(buf.bio_ptr(), self.x509)
        return (buf.read_all() or b"").decode()

    def as_der(self) -> bytes:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.i2d_x509(self.x509)

    def as_pem(self) -> bytes:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf = BIO.MemoryBuffer()
        m2.x509_write_pem(buf.bio_ptr(), self.x509)
        return buf.read() or b""

    def save_pem(self, filename: str) -> int:
        """
        :param filename: name of the file to be loaded
        :return: 1 for success or 0 for failure
        """
        with BIO.openfile(filename, "wb") as bio:
            return m2.x509_write_pem(bio.bio_ptr(), self.x509)

    def save(self, filename: str, format: int = FORMAT_PEM) -> int:
        """
        Saves X.509 certificate to a file. Default output
        format is PEM.

        :param filename: Name of the file the cert will be saved to.

        :param format: Controls what output format is used to save the cert.
                       Either FORMAT_PEM or FORMAT_DER to save in PEM or
                       DER format.  Raises a ValueError if an unknow
                       format is used.

        :return: 1 for success or 0 for failure
        """
        with BIO.openfile(filename, "wb") as bio:
            if format == FORMAT_PEM:
                return m2.x509_write_pem(bio.bio_ptr(), self.x509)
            elif format == FORMAT_DER:
                return m2.i2d_x509_bio(bio.bio_ptr(), self.x509)
            else:
                raise ValueError(
                    "Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER"
                )

    def set_version(self, version: int) -> int:
        """
        Set version of the certificate.

        :param version: Version number.
        :return:        Returns 0 on failure.
        """
        return m2.x509_set_version(self.x509, version)

    def get_version(self) -> int:
        return m2.x509_get_version(self.x509)

    def set_not_before(self, asn1_time: ASN1.ASN1_TIME) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        return m2.x509_set_not_before(self.x509, asn1_time._ptr())

    def set_not_after(self, asn1_time: ASN1.ASN1_TIME) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        return m2.x509_set_not_after(self.x509, asn1_time._ptr())

    def get_not_before(self) -> ASN1.ASN1_TIME:
        time_ptr = m2.x509_get_not_before(self.x509)
        time = ASN1.ASN1_TIME(time_ptr, _pyfree=0)
        time.owner = self
        return time

    def get_not_after(self) -> ASN1.ASN1_TIME:
        time_ptr = m2.x509_get_not_after(self.x509)
        time = ASN1.ASN1_TIME(time_ptr, _pyfree=0)
        time.owner = self
        return time

    def get_serial_number(self) -> int:
        asn1_int = m2.x509_get_serial_number(self.x509)
        py_int = int(ASN1.ASN1_Integer(asn1_int))
        if py_int is None:
            raise X509Error("Could not retrieve serial number")
        return py_int

    def set_serial_number(self, serial: int) -> int:
        """
        Set serial number.

        :param serial:  Serial number.

        :return 1 for success and 0 for failure.
        """
        asn1_integer = ASN1.ASN1_Integer(serial)
        return m2.x509_set_serial_number(self.x509, asn1_integer.asn1int)

    def get_pubkey(self) -> EVP.PKey:
        pkey_ptr = m2.x509_get_pubkey(self.x509)
        if pkey_ptr is None:
            raise X509Error("Could not get public key")
        return EVP.PKey(pkey_ptr, _pyfree=1)

    def set_pubkey(self, pkey: EVP.PKey) -> int:
        """
        Set the public key for the certificate

        :param pkey: Public key

        :return 1 for success and 0 for failure
        """
        return m2.x509_set_pubkey(self.x509, pkey.pkey)

    def get_issuer(self) -> X509_Name:
        return X509_Name(m2.x509_get_issuer_name(self.x509), _pyfree=0)

    def set_issuer(self, name: X509_Name) -> int:
        return m2.x509_set_issuer_name(self.x509, name._ptr())

    set_issuer_name = set_issuer

    def get_subject(self) -> X509_Name:
        return X509_Name(m2.x509_get_subject_name(self.x509), _pyfree=0)

    def set_subject_name(self, name: X509_Name) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        return m2.x509_set_subject_name(self.x509, name._ptr())

    set_subject = set_subject_name

    def add_ext(self, ext: X509_Extension) -> int:
        """
        Add X509 extension to this certificate.

        :param ext:    Extension

        :return 1 for success and 0 for failure
        """
        ext_ptr = ext._ptr()
        if ext_ptr is None:
            raise X509Error("Cannot add an uninitialized extension")
        return m2.x509_add_ext(self.x509, ext_ptr, -1)

    def get_ext_count(self) -> int:
        """
        Get X509 extension count.
        """
        return m2.x509_get_ext_count(self.x509)

    def get_ext_at(self, index: int) -> X509_Extension:
        """
        Get X509 extension by index.

        :param index:    Name of the extension

        :return:        X509_Extension
        """
        if not 0 <= index < self.get_ext_count():
            raise IndexError("index out of range")
        ext_ptr = m2.x509_get_ext(self.x509, index)
        return X509_Extension(ext_ptr, _pyfree=0)

    def get_ext(self, name: str) -> X509_Extension:
        """
        Get X509 extension by name.

        :param name:    Name of the extension

        :return:       X509_Extension
        """
        for i in range(self.get_ext_count()):
            ext = self.get_ext_at(i)
            if ext.get_name() == name:
                return ext
        raise LookupError

    def sign(self, pkey: EVP.PKey, md: str) -> int:
        """
        Sign the certificate.

        :param pkey: Public key

        :param md:   Message digest algorithm to use for signing,
                     for example 'sha1'.

        :return int
        """
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError("unknown message digest", md)
        return m2.x509_sign(self.x509, pkey.pkey, mda())

    def verify(self, pkey: Optional[EVP.PKey] = None) -> int:
        if pkey:
            return m2.x509_verify(self.x509, pkey.pkey)
        else:
            pubkey = self.get_pubkey()
            return m2.x509_verify(self.x509, pubkey.pkey)

    def check_ca(self) -> int:
        """
        Check if the certificate is a Certificate Authority (CA) certificate.

        :return: 0 if the certificate is not CA, nonzero otherwise.

        :requires: OpenSSL 0.9.8 or newer
        """
        return m2.x509_check_ca(self.x509)

    def check_purpose(self, id: int, ca: int) -> int:
        """
        Check if the certificate's purpose matches the asked purpose.

        :param id: Purpose id. See X509_PURPOSE_* constants.

        :param ca: 1 if the certificate should be CA, 0 otherwise.

        :return: 0 if the certificate purpose does not match, nonzero
                 otherwise.
        """
        return m2.x509_check_purpose(self.x509, id, ca)

    def get_fingerprint(self, md: str = "sha1") -> str:
        """
        Get the fingerprint of the certificate.

        :param md: Message digest algorithm to use.

        :return:   String containing the fingerprint in hex format.
        """
        md_obj = EVP.MessageDigest(md)
        md_obj.update(self.as_der())
        digest = md_obj.final()
        return binascii.hexlify(digest).upper().decode()

    def add_subject_key_identifier(self) -> int:
        """
        Adds a Subject Key Identifier (SKI) extension to the certificate,
        calculating the key identifier from the certificate's public key.

        This bypasses the error-prone use of 'subjectKeyIdentifier', 'hash'
        in new_extension, which requires a pre-configured OpenSSL context.

        :return: 1 for success and 0 for failure.
        """
        pkey = self.get_pubkey()
        # The SKID value is typically the SHA1 hash of the public key's contents.
        # We compute the hash manually and then format it for the extension value.
        skid_digest = pkey.get_key_identifier()

        # Format the digest into the required OpenSSL extension value string format:
        # A list of hex octets separated by colons (e.g., 'A1:B2:C3:D4:...')
        value = ":".join(f"{b:02X}" for b in skid_digest)

        # Create the extension directly with the computed value
        # Note: SKID is usually non-critical (critical=0 by default for new_extension)
        ext = new_extension("subjectKeyIdentifier", value)

        # Add the extension to the certificate object
        return self.add_ext(ext)


def load_cert(file: Union[str, bytes], format: int = FORMAT_PEM) -> X509:
    """
    Load certificate from file.

    :param file: Name of file containing certificate in either DER or
                 PEM format.

    :param format: Describes the format of the file to be loaded,
                   either PEM or DER.

    :return: M2Crypto.X509.X509 object.
    """
    if isinstance(file, bytes):
        file = file.decode()
    with BIO.openfile(file) as bio:
        if format == FORMAT_PEM:
            return load_cert_bio(bio)
        elif format == FORMAT_DER:
            cptr = m2.d2i_x509(bio._ptr())
            return X509(cptr, _pyfree=1)
        else:
            raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")


def load_cert_bio(bio: BIO.BIO, format: int = FORMAT_PEM) -> X509:
    """
    Load certificate from a bio.

    :param bio: BIO pointing at a certificate in either DER or PEM format.

    :param format: Describes the format of the cert to be loaded,
                   either PEM or DER (via constants FORMAT_PEM
                   and FORMAT_FORMAT_DER)

    :return: M2Crypto.X509.X509 object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509(bio._ptr())
    else:
        raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")
    if cptr is None:
        raise X509Error("Failed to load certificate from BIO")
    return X509(cptr, _pyfree=1)


def load_cert_string(string: Union[str, bytes], format: int = FORMAT_PEM) -> X509:
    """
    Load certificate from a cert_str.

    :param cert_str: String containing a certificate in either
                     DER or PEM format.

    :param format: Describes the format of the cert to be loaded,
                   either PEM or DER (via constants FORMAT_PEM
                   and FORMAT_FORMAT_DER)

    :return: M2Crypto.X509.X509 object.
    """
    if isinstance(string, str):
        string = string.encode("utf-8")
    bio = BIO.MemoryBuffer(string)
    return load_cert_bio(bio, format)


def load_cert_der_string(cert_str: Union[str, bytes]) -> X509:
    """
    Load certificate from a cert_str.

    :param cert_str: String containing a certificate in DER format.

    :return: M2Crypto.X509.X509 object.
    """
    if isinstance(cert_str, str):
        cert_str = cert_str.encode("utf-8")
    return load_cert_string(cert_str, FORMAT_DER)


class X509_Stack(object):
    """
    X509 Stack

    :warning: Do not modify the underlying OpenSSL stack
              except through this interface, or use any OpenSSL
              functions that do so indirectly. Doing so will get the
              OpenSSL stack and the internal pystack of this class out
              of sync, leading to python memory leaks, exceptions or
              even python crashes!
    """

    def __init__(
        self,
        stack: Optional[C.STACK_OF_X509] = None,
        _pyfree: int = 0,
        _pyfree_x509: int = 0,
    ) -> None:
        """
        :param stack: OpenSSL STACK_OF(X509)
        """
        self.pystack: List[X509] = []
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            num = m2.sk_x509_num(self.stack)
            for i in range(num):
                self.pystack.append(
                    X509(m2.sk_x509_value(self.stack, i), _pyfree=_pyfree_x509)
                )
        else:
            self.stack = m2.sk_x509_new_null()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.sk_x509_free(self.stack)

    def __len__(self) -> int:
        return len(self.pystack)

    def __getitem__(self, idx: int) -> X509:
        return self.pystack[idx]

    def __iter__(self) -> Iterator[X509]:
        return iter(self.pystack)

    def _ptr(self) -> C.STACK_OF_X509:
        return self.stack

    def push(self, x509: X509) -> int:
        """
        push an X509 certificate onto the stack.

        :param x509: X509 object.

        :return: The number of X509 objects currently on the stack.
        """
        self.pystack.append(x509)
        return m2.sk_x509_push(self.stack, x509._ptr())

    def pop(self) -> Optional[X509]:
        """
        pop a certificate from the stack.

        :return: X509 object that was popped, or None if there is
                 nothing to pop.
        """
        x509_ptr = m2.sk_x509_pop(self.stack)
        if x509_ptr is None:
            # Sanity check: our Python list should also be empty.
            assert not self.pystack
            return None
        return self.pystack.pop()

    def as_der(self) -> bytes:
        """
        Return the stack as a DER encoded string
        """
        return m2.get_der_encoding_stack(self.stack)


class X509_Store_Context(object):
    """
    X509 Store Context
    """

    def __init__(self, x509_store_ctx: C.X509_STORE_CTX, _pyfree: int = 0) -> None:
        """

        :param x509_store_ctx: binary data for
              OpenSSL X509_STORE_CTX type
        """
        self.ctx = x509_store_ctx
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_store_ctx_free(self.ctx)

    def _ptr(self) -> C.X509_STORE_CTX:
        return self.ctx

    def get_current_cert(self) -> Optional[X509]:
        """
        Get current X.509 certificate.

        :warning: The returned certificate is NOT refcounted, so you can not
                  rely on it being valid once the store context goes
                  away or is modified.
        """
        cert_ptr = m2.x509_store_ctx_get_current_cert(self.ctx)
        if cert_ptr is None:
            return None
        return X509(cert_ptr, _pyfree=0)

    def get_error(self) -> int:
        """
        Get error code.
        """
        return m2.x509_store_ctx_get_error(self.ctx)

    def get_error_depth(self) -> int:
        """
        Get error depth.
        """
        return m2.x509_store_ctx_get_error_depth(self.ctx)

    def get1_chain(self) -> X509_Stack:
        """
        Get certificate chain.

        :return: Reference counted (i.e. safe to use even after the store
                 context goes away) stack of certificates in the
                 chain as X509_Stack.
        """
        return X509_Stack(m2.x509_store_ctx_get1_chain(self.ctx), 1, 1)


def x509_store_default_cb(ok: int, ctx: C.X509_STORE_CTX) -> int:
    return ok


class X509_Store(object):
    """
    X509 Store
    """

    def __init__(self, store: Optional[C.X509_STORE] = None, _pyfree: int = 0) -> None:
        """
        :param store: binary data for OpenSSL X509_STORE_CTX type.
        """
        if store is not None:
            self.store = store
            self._pyfree = _pyfree
        else:
            self.store = m2.x509_store_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_store_free(self.store)

    def _ptr(self) -> C.X509_STORE:
        return self.store

    def load_info(self, file: str) -> int:
        """
        :param file: filename

        :return: 1 on success, 0 on failure
        """
        return m2.x509_store_load_locations(self.store, file)

    load_locations = load_info

    def add_x509(self, x509: X509) -> int:
        """
        Add X509 certificate to the store.
        """
        return m2.x509_store_add_cert(self.store, x509._ptr())

    add_cert = add_x509

    def set_verify_cb(
        self, callback: Optional[Callable[[int, C.X509_STORE_CTX], int]] = None
    ) -> None:
        """
        Set callback which will be called when the store is verified.
        Wrapper over OpenSSL X509_STORE_set_verify_cb().

        :param callback:    Callable to specify verification options.
                            Type of the callable must be:
                            (int, X509_Store_Context) -> int.
                            If None: set the standard options.

        :note: compile-time or run-time errors in the callback would result
               in mysterious errors during verification, which could be hard
               to trace.

        :note: Python exceptions raised in callbacks do not propagate to
               verify() call.

        :return: None
        """
        if callback is None:
            callback = x509_store_default_cb

        if not callable(callback):
            raise X509Error("set_verify(): callback is not callable")

        m2.x509_store_set_verify_cb(self.store, callback)

    def set_flags(self, flags: int) -> int:
        """
        Set the verification flags for the X509Store
        Wrapper over OpenSSL X509_STORE_set_flags()

        :param flags: `VERIFICATION FLAGS` section of the
                      X509_VERIFY_PARAM_set_flags man page has
                      a complete description of values the flags
                      parameter can take.
                      Their M2Crypto equivalent is transformed following
                      the pattern: "X509_V_FLAG_XYZ" -> lowercase("VERIFY_XYZ")
        """
        return m2.x509_store_set_flags(self.store, flags)


def new_stack_from_der(der_string: bytes) -> X509_Stack:
    """
    Create a new X509_Stack from DER string.
    """
    stack_ptr = m2.make_stack_from_der_sequence(der_string)
    if stack_ptr is None:
        raise X509Error("Failed to create stack from DER sequence")
    return X509_Stack(stack_ptr, 1, 1)


class Request(object):
    """
    X509 Certificate Request.
    """

    def __init__(self, req: Optional[C.X509_REQ] = None, _pyfree: int = 0) -> None:
        if req is not None:
            self.req = req
            self._pyfree = _pyfree
        else:
            self.req = m2.x509_req_new()
            m2.x509_req_set_version(self.req, 0)
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_req_free(self.req)

    def _ptr(self) -> C.X509_REQ:
        return self.req

    def as_text(self) -> str:
        buf = BIO.MemoryBuffer()
        m2.x509_req_print(buf.bio_ptr(), self.req)
        return (buf.read_all() or b"").decode()

    def as_pem(self) -> bytes:
        buf = BIO.MemoryBuffer()
        m2.x509_req_write_pem(buf.bio_ptr(), self.req)
        return buf.read() or b""

    def as_der(self) -> bytes:
        buf = BIO.MemoryBuffer()
        m2.i2d_x509_req_bio(buf.bio_ptr(), self.req)
        return buf.read() or b""

    def save_pem(self, filename: str) -> int:
        with BIO.openfile(filename, "wb") as bio:
            return m2.x509_req_write_pem(bio.bio_ptr(), self.req)

    def save(self, filename: str, format: int = FORMAT_PEM) -> int:
        """
        Saves X.509 certificate request to a file. Default output
        format is PEM.

        :param filename: Name of the file the request will be s: aved to.

                       request. Either FORMAT_PEM or FORMAT_DER to save
                       in PEM or DER format. Raises V:  a lueError if an
                       unknown format is used.

        :return: 1 for success, 0 for failure.
                 The error code can be obtained by ERR_get_error.
        """
        with BIO.openfile(filename, "wb") as bio:
            if format == FORMAT_PEM:
                return m2.x509_req_write_pem(bio.bio_ptr(), self.req)
            elif format == FORMAT_DER:
                return m2.i2d_x509_req_bio(bio.bio_ptr(), self.req)
            else:
                raise ValueError(
                    "Unknown filetype. Must be either FORMAT_DER or FORMAT_PEM"
                )

    def get_pubkey(self) -> EVP.PKey:
        """
        Get the public key for the request.

        :return:     Public key from the request.
        """
        pkey_ptr = m2.x509_req_get_pubkey(self.req)
        if pkey_ptr is None:
            raise X509Error("Could not get public key from request")
        return EVP.PKey(pkey_ptr, _pyfree=1)

    def set_pubkey(self, pkey: EVP.PKey) -> int:
        """
        Set the public key for the request.

        :param pkey: Public key

        :return:     Return 1 for success and 0 for failure.
        """
        return m2.x509_req_set_pubkey(self.req, pkey.pkey)

    def get_subject(self) -> X509_Name:
        return X509_Name(m2.x509_req_get_subject_name(self.req), _pyfree=0)

    def set_subject_name(self, name: X509_Name) -> int:
        """
        Set subject name.

        :param name:    subjectName field.
        :return:    1 for success and 0 for failure
        """
        return m2.x509_req_set_subject_name(self.req, name._ptr())

    set_subject = set_subject_name

    def add_extensions(self, ext_stack: X509_Extension_Stack) -> int:
        """
        Add X509 extensions to this request.

        :param ext_stack: Stack of extensions to add.
        :return: 1 for success and 0 for failure
        """
        return m2.x509_req_add_extensions(self.req, ext_stack._ptr())

    def verify(self, pkey: EVP.PKey) -> int:
        """

        :param pkey: PKey to be verified
        :return: 1 for success and 0 for failure
        """
        return m2.x509_req_verify(self.req, pkey.pkey)

    def sign(self, pkey: EVP.PKey, md: str) -> int:
        """

        :param pkey: PKey to be signed
        :param md: used algorigthm
        :return: 1 for success and 0 for failure
        """
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError("unknown message digest", md)
        return m2.x509_req_sign(self.req, pkey.pkey, mda())

    def get_version(self) -> int:
        """
        Get the version of the request.
        :return: Version number.
        """
        return m2.x509_req_get_version(self.req)

    def set_version(self, ver: int) -> int:
        """
        Set the version of the request.
        :param ver: Version number.
        :return: 1 for success, 0 for failure.
        """
        return m2.x509_req_set_version(self.req, ver)


def load_request(file: Union[str, bytes], format: int = FORMAT_PEM) -> Request:
    """
    Load certificate request from file.

    :param file: Name of file containing certificate request in
                 either PEM or DER format.
    :param format: Describes the format of the file to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)
    :return: Request object.
    """
    if isinstance(file, bytes):
        file = file.decode()
    with BIO.openfile(file) as f:
        if format == FORMAT_PEM:
            cptr = m2.x509_req_read_pem(f.bio_ptr())
        elif format == FORMAT_DER:
            cptr = m2.d2i_x509_req(f.bio_ptr())
        else:
            raise ValueError(
                "Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER"
            )

    if cptr is None:
        raise X509Error("Failed to load request from file")

    return Request(cptr, 1)


def load_request_bio(bio: BIO.BIO, format: int = FORMAT_PEM) -> Request:
    """
    Load certificate request from a bio.

    :param bio: BIO pointing at a certificate request in
                either DER or PEM format.
    :param format: Describes the format of the request to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)
    :return: M2Crypto.X509.Request object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_req_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509_req(bio._ptr())
    else:
        raise ValueError("Unknown format. Must be either FORMAT_DER or FORMAT_PEM")
    if cptr is None:
        raise X509Error("Failed to load request from BIO")
    return Request(cptr, _pyfree=1)


def load_request_string(string: Union[str, bytes], format: int = FORMAT_PEM) -> Request:
    """
    Load certificate request from a cert_str.

    :param cert_str: String containing a certificate request in
                     either DER or PEM format.
    :param format: Describes the format of the request to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)

    :return: M2Crypto.X509.Request object.
    """
    if isinstance(string, str):
        string = string.encode("utf-8")
    bio = BIO.MemoryBuffer(string)
    return load_request_bio(bio, format)


def load_request_der_string(cert_str: Union[str, bytes]) -> Request:
    """
    Load certificate request from a cert_str.

    :param cert_str: String containing a certificate request in DER format.
    :return: M2Crypto.X509.Request object.
    """
    cert_str = cert_str.encode() if isinstance(cert_str, str) else cert_str
    return load_request_string(cert_str, FORMAT_DER)


class CRL(object):
    """
    X509 Certificate Revocation List
    """

    def __init__(self, crl: Optional[C.X509_CRL] = None, _pyfree: int = 0) -> None:
        """

        :param crl: binary representation of
               the underlying OpenSSL X509_CRL object.
        """
        if crl is not None:
            self.crl = crl
            self._pyfree = _pyfree
        else:
            self.crl = m2.x509_crl_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, "_pyfree", 0):
            m2.x509_crl_free(self.crl)

    def as_text(self) -> str:
        """
        Return CRL in PEM format in a string.

        :return: String containing the CRL in PEM format.
        """
        buf = BIO.MemoryBuffer()
        m2.x509_crl_print(buf.bio_ptr(), self.crl)
        return (buf.read_all() or b"").decode()


def load_crl(file: str) -> CRL:
    """
    Load CRL from file.

    :param file: Name of file containing CRL in PEM format.

    :return: M2Crypto.X509.CRL object.
    """
    with BIO.openfile(file) as f:
        cptr = m2.x509_crl_read_pem(f.bio_ptr())
    if cptr is None:
        raise X509Error("Failed to load CRL from file")
    return CRL(cptr, 1)
