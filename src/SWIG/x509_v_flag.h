/* Errors in case a check in X509_V_FLAG_X509_STRICT mode fails */
#define X509_V_FLAG_CB_ISSUER_CHECK 0x0
#define X509_V_FLAG_USE_CHECK_TIME 0x2
#define X509_V_FLAG_CRL_CHECK 0x4
#define X509_V_FLAG_CRL_CHECK_ALL 0x8
#define X509_V_FLAG_IGNORE_CRITICAL 0x10
#define X509_V_FLAG_X509_STRICT 0x20
#define X509_V_FLAG_ALLOW_PROXY_CERTS 0x40
#define X509_V_FLAG_POLICY_CHECK 0x80
#define X509_V_FLAG_EXPLICIT_POLICY 0x100
#define X509_V_FLAG_INHIBIT_ANY 0x200
#define X509_V_FLAG_INHIBIT_MAP 0x400
#define X509_V_FLAG_NOTIFY_POLICY 0x800
#define X509_V_FLAG_EXTENDED_CRL_SUPPORT 0x1000
#define X509_V_FLAG_USE_DELTAS 0x2000
#define X509_V_FLAG_CHECK_SS_SIGNATURE 0x4000
#define X509_V_FLAG_TRUSTED_FIRST 0x8000
#define X509_V_FLAG_SUITEB_128_LOS_ONLY 0x10000
#define X509_V_FLAG_SUITEB_192_LOS 0x20000
#define X509_V_FLAG_SUITEB_128_LOS 0x30000
#define X509_V_FLAG_PARTIAL_CHAIN 0x80000
#define X509_V_FLAG_NO_ALT_CHAINS 0x100000
#define X509_V_FLAG_NO_CHECK_TIME 0x200000
#define X509_V_FLAG_POLICY_MASK (X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY | X509_V_FLAG_INHIBIT_ANY | X509_V_FLAG_INHIBIT_MAP)