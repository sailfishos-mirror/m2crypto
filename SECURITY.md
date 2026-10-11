# Security Policy

## Supported versions

Security fixes are made on the `master` branch and released in the next
M2Crypto release. Older releases do not get backports; please upgrade
to the latest release.

## Reporting a vulnerability

Please do **not** report security problems in the public issue tracker.

Send an email to the maintainer, Matěj Cepl <mcepl@cepl.eu>, with
"M2Crypto security" in the subject. Encrypted email is welcome; the
OpenPGP key is available from public keyservers for that address.

Useful things to include:

- the affected M2Crypto version or commit, and the OpenSSL version
- a description of the problem and its impact
- steps or a minimal script to reproduce it, if you have one
- whether you would like to be credited, and under which name

If the report was found with the help of automated tools or an LLM,
please say so and confirm that you checked the finding yourself.

## What happens next

- You should get an acknowledgement within a week.
- We will confirm the problem, prepare a fix and agree with you on
  a release date. The default embargo is 90 days from the report.
- Once the fixed release is out, we publish an advisory, request a CVE
  where appropriate, and credit the reporter unless they prefer not to
  be named.

M2Crypto is maintained by volunteers, so please be patient with us.

## Scope

M2Crypto is a thin wrapper around OpenSSL. Vulnerabilities in OpenSSL
itself should be reported to the OpenSSL project
(<https://openssl-library.org/community/vulnerability-reporting/>).
Problems in how M2Crypto uses OpenSSL, or in its own Python and C code,
belong here.
