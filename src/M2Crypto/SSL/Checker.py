"""
SSL peer certificate checking routines

Copyright (c) 2004-2007 Open Source Applications Foundation.
All rights reserved.

Copyright 2008 Heikki Toivonen. All rights reserved.
"""

__all__ = [
    "SSLVerificationError",
    "NoCertificate",
    "WrongCertificate",
    "WrongHost",
    "Checker",
]

import re
import socket
import ipaddress

from M2Crypto import X509, m2  # noqa
from typing import Optional, Union  # noqa

try:
    from re import Pattern
except ImportError:
    from typing import Pattern


class SSLVerificationError(Exception):
    pass


class NoCertificate(SSLVerificationError):
    pass


class WrongCertificate(SSLVerificationError):
    pass


class WrongHost(SSLVerificationError):
    def __init__(
        self,
        expectedHost: str,
        actualHost: Union[str, bytes],
        fieldName: str = "commonName",
    ) -> None:
        """
        This exception will be raised if the certificate returned by the
        peer was issued for a different host than we tried to connect to.
        This could be due to a server misconfiguration or an active attack.

        :param expectedHost: The name of the host we expected to find in the
                             certificate.
        :param actualHost:   The name of the host we actually found in the
                             certificate.
        :param fieldName:    The field name where we noticed the error. This
                             should be either 'commonName' or 'subjectAltName'.
        """
        if fieldName not in ("commonName", "subjectAltName"):
            raise ValueError(
                "Unknown fieldName, should be either commonName " + "or subjectAltName"
            )

        SSLVerificationError.__init__(self)
        self.expectedHost = expectedHost
        self.actualHost = actualHost
        self.fieldName = fieldName

    def __str__(self) -> str:
        actual = (
            self.actualHost.decode()
            if isinstance(self.actualHost, bytes)
            else self.actualHost
        )
        return "Peer certificate %s does not match host, expected %s, got %s" % (
            self.fieldName,
            self.expectedHost,
            actual,
        )


def _ipAddressText(text: str) -> Optional[str]:
    """Return the canonical text of an IP address literal, or None."""
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


class Checker:
    """Post-connection check of the peer certificate.

    Hostname matching is delegated to OpenSSL (X509_check_host(3)).
    ``hostCheckFlags`` holds the X509_CHECK_FLAG_* flags passed to it;
    the default rejects partial wildcards such as ``m*.example.com``.
    Set it to 0 on an instance (or subclass) to accept them again.
    """

    # COMPATIBILITY: re.Pattern is available only from Python 3.7+
    numericIpMatch: Pattern[str] = re.compile(r"^[0-9]+(\.[0-9]+)*$")

    hostCheckFlags: int = m2.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS

    def __init__(
        self,
        host: Optional[str] = None,
        peerCertHash: Optional[bytes] = None,
        peerCertDigest: str = "sha256",
    ) -> None:
        self.host = host
        self.fingerprint = peerCertHash
        self.digest: str = peerCertDigest

    def __call__(
        self, peerCert: Optional[X509.X509], host: Optional[str] = None
    ) -> bool:
        if peerCert is None:
            raise NoCertificate("peer did not return certificate")

        if host is not None:
            self.host = host

        if self.fingerprint:
            if self.digest not in ("sha256"):
                raise ValueError('unsupported digest "%s"' % self.digest)

            if self.digest == "sha256":
                expected_len = 64
            else:
                raise ValueError("Unexpected digest {0}".format(self.digest))

            if len(self.fingerprint) != expected_len:
                raise WrongCertificate(
                    (
                        "peer certificate fingerprint length does not match\n"
                        + "fingerprint: {0}\nexpected = {1}\n"
                        + "observed = {2}"
                    ).format(
                        self.fingerprint.decode(),
                        expected_len,
                        len(self.fingerprint),
                    )
                )

            expected_fingerprint = (
                self.fingerprint.decode()
                if isinstance(self.fingerprint, bytes)
                else self.fingerprint
            )
            observed_fingerprint = peerCert.get_fingerprint(md=self.digest)
            if observed_fingerprint != expected_fingerprint:
                raise WrongCertificate(
                    (
                        "peer certificate fingerprint does not match\n"
                        + "expected = {0},\n"
                        + "observed = {1}"
                    ).format(expected_fingerprint, observed_fingerprint)
                )

        if self.host:
            self._checkHost(peerCert, self.host)

        return True

    def _checkHost(self, peerCert: X509.X509, host: Union[str, bytes]) -> None:
        """Verify that peerCert was issued for host.

        Matching is done by OpenSSL (X509_check_host(3) and
        X509_check_ip_asc(3)) on the structured subjectAltName, never on
        its printed text.  The commonName is consulted only when the
        certificate has no subjectAltName of the relevant type (RFC 6125).

        :raises WrongHost: if the certificate does not match host.
        :raises WrongCertificate: if the certificate has neither
                                  subjectAltName nor commonName.
        """
        host_str = host.decode() if isinstance(host, bytes) else host
        ip_host = _ipAddressText(host_str)

        try:
            san_types = {gen_type for gen_type, _ in peerCert.get_subject_alt_names()}
        except X509.X509Error as exc:
            raise WrongCertificate(str(exc))

        # Kept for backwards compatibility; nothing reads it any more.
        self.useSubjectAltNameOnly = bool(san_types & {m2.GEN_DNS, m2.GEN_IPADD})

        if ip_host is not None:
            if m2.x509_check_ip_asc(peerCert.x509, ip_host, 0) == 1:
                return
        else:
            flags = self.hostCheckFlags
            if self.useSubjectAltNameOnly:
                # Legacy rule: any DNS or IP SAN disables commonName.
                flags |= m2.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
            ret = m2.x509_check_host(peerCert.x509, host_str, flags)
            if ret == 1:
                return
            if ret < 0:
                raise WrongCertificate(
                    "cannot check host %r against peer certificate" % host_str
                )

        commonNames = [
            entry.get_data().as_text()
            for entry in peerCert.get_subject().get_entries_by_nid(m2.NID_commonName)
        ]

        if self.useSubjectAltNameOnly:
            raise WrongHost(
                expectedHost=host_str,
                actualHost=self._describeSubjectAltName(peerCert),
                fieldName="subjectAltName",
            )

        if ip_host is not None:
            # X509_check_ip_asc() never looks at the commonName. Keep the
            # old exact-match fallback for certificates without any SAN.
            for commonName in commonNames:
                if _ipAddressText(commonName) == ip_host:
                    return

        if not commonNames:
            raise WrongCertificate("no commonName in peer certificate")

        raise WrongHost(
            expectedHost=host_str,
            actualHost=",".join(commonNames),
            fieldName="commonName",
        )

    @staticmethod
    def _describeSubjectAltName(peerCert: X509.X509) -> str:
        """Printable subjectAltName, for error messages only."""
        try:
            return peerCert.get_ext("subjectAltName").get_value()
        except LookupError:
            return ""

    def _splitSubjectAltName(
        self,
        host: Union[str, bytes],
        subjectAltName: Union[str, bytes],
    ) -> bool:
        """Legacy helper matching host against printed subjectAltName text.

        .. deprecated::
           Not used by :class:`Checker` any more and unsafe for security
           decisions: OpenSSL does not escape ',' inside URI, email or
           otherName values, so the text cannot be split reliably. Use
           :meth:`M2Crypto.X509.X509.get_subject_alt_names` instead.

        >>> check = Checker()
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:my.example.com')
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:*.example.com')
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:m*.example.com')
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:m*ample.com')
        False
        >>> check.useSubjectAltNameOnly
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:m*ample.com, othername:<unsupported>')
        False
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:m*ample.com, DNS:my.example.org')
        False
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:m*ample.com, DNS:my.example.com')
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='DNS:my.example.com, DNS:my.example.org')
        True
        >>> check._splitSubjectAltName(host='xn--bcher-kva.example',
        ...     subjectAltName='DNS:xn--bcher-kva.example')
        True
        >>> check._splitSubjectAltName(host='xn--bcher-kva.example',
        ...     subjectAltName='DNS:*.example')
        True
        >>> check._splitSubjectAltName(host='xn--bcher-kva.example',
        ...     subjectAltName='DNS:xn--caf-dma.example')
        False
        >>> check._splitSubjectAltName(host='xn--c1yn36f.example',
        ...     subjectAltName='DNS:xn--c1yn36f.example')
        True
        >>> check.useSubjectAltNameOnly
        True
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='')
        False
        >>> check._splitSubjectAltName(host='my.example.com',
        ...     subjectAltName='othername:<unsupported>')
        False
        >>> check.useSubjectAltNameOnly
        False
        """
        host_str = host.decode() if isinstance(host, bytes) else host
        san_str = (
            subjectAltName.decode()
            if isinstance(subjectAltName, bytes)
            else subjectAltName
        )

        self.useSubjectAltNameOnly = False
        for certHost in san_str.split(","):
            certHost = certHost.lower().strip()
            if certHost[:4] == "dns:":
                self.useSubjectAltNameOnly = True
                if self._match(host_str, certHost[4:]):
                    return True
            elif certHost[:11] == "ip address:":
                self.useSubjectAltNameOnly = True
                if self._matchIPAddress(host_str, certHost[11:]):
                    return True
        return False

    def _match(self, host: str, certHost: str) -> bool:
        """
        >>> check = Checker()
        >>> check._match(host='my.example.com', certHost='my.example.com')
        True
        >>> check._match(host='my.example.com', certHost='*.example.com')
        True
        >>> check._match(host='my.example.com', certHost='m*.example.com')
        True
        >>> check._match(host='my.example.com', certHost='m*.EXAMPLE.com')
        True
        >>> check._match(host='my.example.com', certHost='m*ample.com')
        False
        >>> check._match(host='my.example.com', certHost='*.*.com')
        False
        >>> check._match(host='1.2.3.4', certHost='1.2.3.4')
        True
        >>> check._match(host='1.2.3.4', certHost='*.2.3.4')
        False
        >>> check._match(host='1234', certHost='1234')
        True
        >>> check._match(host='xn--bcher-kva.example',
        ...     certHost='xn--bcher-kva.example')
        True
        >>> check._match(host='xn--bcher-kva.example', certHost='*.example')
        True
        >>> check._match(host='xn--bcher-kva.example',
        ...     certHost='xn--caf-dma.example')
        False
        """
        # XXX See RFC 2818 and 3280 for matching rules, this is may not
        # XXX yet be complete.

        host = host.lower()
        certHost = certHost.lower()

        if host == certHost:
            return True

        if certHost.count("*") > 1:
            # Not sure about this, but being conservative
            return False

        if self.numericIpMatch.match(host) or self.numericIpMatch.match(
            certHost.replace("*", "")
        ):
            # Not sure if * allowed in numeric IP, but think not.
            return False

        if certHost.find("\\") > -1:
            # A backslash is not valid in a DNS name. re.escape()
            # below would treat it literally and it would simply
            # fail to match, but reject it outright so such names
            # never reach matching.
            return False

        # Treat certificate names literally except for the
        # supported wildcard.
        certHost = re.escape(certHost).replace(r"\*", r"[^.]*")
        return re.fullmatch(certHost, host) is not None

    def _matchIPAddress(
        self, host: Union[str, bytes], certHost: Union[str, bytes]
    ) -> bool:
        """
        >>> check = Checker()
        >>> check._matchIPAddress(host='my.example.com',
        ...     certHost='my.example.com')
        False
        >>> check._matchIPAddress(host='1.2.3.4', certHost='1.2.3.4')
        True
        >>> check._matchIPAddress(host='1.2.3.4', certHost='*.2.3.4')
        False
        >>> check._matchIPAddress(host='1.2.3.4', certHost='1.2.3.40')
        False
        >>> check._matchIPAddress(host='::1', certHost='::1')
        True
        >>> check._matchIPAddress(host='::1', certHost='0:0:0:0:0:0:0:1')
        True
        >>> check._matchIPAddress(host='::1', certHost='::2')
        False
        """
        host_str = host.decode() if isinstance(host, bytes) else host
        certHost_str = certHost.decode() if isinstance(certHost, bytes) else certHost
        try:
            return ipaddress.ip_address(host_str) == ipaddress.ip_address(certHost_str)
        except ValueError:
            return False


if __name__ == "__main__":
    import doctest

    doctest.testmod()
