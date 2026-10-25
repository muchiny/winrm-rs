// Throwaway PKI material for the Certificate-auth unit tests.
//
// Self-signed, generated once with OpenSSL 3.5 and never used anywhere else;
// these are NOT secrets. Regenerate with:
//
//   openssl ecparam -name prime256v1 -genkey -noout -out ec-sec1.key
//   openssl req -x509 -new -key ec-sec1.key -subj "/CN=winrm-rs throwaway EC test" \
//       -days 36500 -addext "extendedKeyUsage=clientAuth,serverAuth" \
//       -addext "subjectAltName=DNS:localhost" -out ec.pem
//   openssl pkcs8 -topk8 -nocrypt -in ec-sec1.key -out ec-pkcs8.key
//   openssl genrsa -traditional -out rsa-pkcs1.key 2048
//   openssl req -x509 -new -key rsa-pkcs1.key -subj "/CN=winrm-rs throwaway RSA test" \
//       -days 36500 -addext "extendedKeyUsage=clientAuth" -out rsa.pem
//   openssl pkcs8 -topk8 -v2 aes-256-cbc -in ec-sec1.key -passout pass:throwaway \
//       -out ec-pkcs8-enc.key
//   openssl ec -in ec-sec1.key -aes128 -passout pass:throwaway -out ec-sec1-enc.key
//   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256   # impostor key
//
// Trust-anchor fixtures (CA, a CA-issued leaf, a non-CA self-signed leaf), made
// with OpenSSL 3.5 and equally throwaway:
//
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key \
//       -out ca.pem -days 36500 -subj "/CN=winrm-rs throwaway test CA"   # default v3_ca: CA:TRUE
//   printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n' > leaf.ext
//   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key \
//       -out leaf.csr -subj "/CN=winrm-rs throwaway CA-issued leaf"
//   openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 2 -days 36500 \
//       -extfile leaf.ext -out leaf.pem
//   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ss.key \
//       -out ss.csr -subj "/CN=winrm-rs throwaway non-CA self-signed"
//   openssl x509 -req -in ss.csr -key ss.key -set_serial 3 -days 36500 -extfile leaf.ext -out ss.pem
//
// Check with `openssl x509 -noout -ext basicConstraints,subjectAltName -in <file>`.
//
// One EC key in two encodings (SEC1, PKCS#8) and one RSA key in PKCS#1 cover
// the three private-key formats Certificate auth accepts. The impostor key is
// unrelated to any certificate here.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Self-signed P-256 certificate (`CN=winrm-rs throwaway EC test`, SAN `localhost`).
pub(crate) const EC_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB2DCCAX6gAwIBAgIUUqaMKtOm51hurmKlXIQ96jaFS6QwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwad2lucm0tcnMgdGhyb3dhd2F5IEVDIHRlc3QwIBcNMjYxMDIx
MTUxODUyWhgPMjEyNjA5MjcxNTE4NTJaMCUxIzAhBgNVBAMMGndpbnJtLXJzIHRo
cm93YXdheSBFQyB0ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEROpKZXQK
rNUKpA9P1HmKmQVo+tKB/MhxXN6yjziwhjqSBWUHxhC2OzUsGAPeuTdLF326lfkO
beFJyZjmrL4/dKOBiTCBhjAdBgNVHQ4EFgQUtfqXlFHCtNmPmWj6NPIT0SR7D08w
HwYDVR0jBBgwFoAUtfqXlFHCtNmPmWj6NPIT0SR7D08wDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9j
YWxob3N0MAoGCCqGSM49BAMCA0gAMEUCIBtJjwIRLUZrQdKDmdrOlBBI5KPfVcsG
koySnOGaSI9xAiEAnlCMdQbfDAQpp3i9w9M2UCeHia4DZzG+kSK8NOKSx44=
-----END CERTIFICATE-----
";

/// SHA-256 fingerprint of [`EC_CERT_PEM`] as `openssl x509 -fingerprint
/// -sha256 -noout` prints it, in lower case (a known-answer vector for the
/// pin).
pub(crate) const EC_CERT_SHA256_OPENSSL: &str = "a7:65:5d:cc:be:aa:e6:bc:34:44:5a:6a:76:36:7f:33:\
     17:3b:aa:f1:27:ad:b0:7e:40:d8:f0:c4:eb:de:6f:64";

/// Key of [`EC_CERT_PEM`], SEC1 encoding (`EC PRIVATE KEY`).
pub(crate) const EC_KEY_SEC1_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINN0vbm3e8bMGlZIxiL0hNnhVRUD0r1lBYVxcSGj+pi5oAoGCCqGSM49
AwEHoUQDQgAEROpKZXQKrNUKpA9P1HmKmQVo+tKB/MhxXN6yjziwhjqSBWUHxhC2
OzUsGAPeuTdLF326lfkObeFJyZjmrL4/dA==
-----END EC PRIVATE KEY-----
";

/// Key of [`EC_CERT_PEM`], PKCS#8 encoding (`PRIVATE KEY`).
pub(crate) const EC_KEY_PKCS8_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg03S9ubd7xswaVkjG
IvSE2eFVFQPSvWUFhXFxIaP6mLmhRANCAARE6kpldAqs1QqkD0/UeYqZBWj60oH8
yHFc3rKPOLCGOpIFZQfGELY7NSwYA965N0sXfbqV+Q5t4UnJmOasvj90
-----END PRIVATE KEY-----
";

/// Self-signed RSA-2048 certificate (`CN=winrm-rs throwaway RSA test`).
pub(crate) const RSA_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIUdriuGuTg4DrjqsO2LojYLXr12J0wDQYJKoZIhvcNAQEL
BQAwJjEkMCIGA1UEAwwbd2lucm0tcnMgdGhyb3dhd2F5IFJTQSB0ZXN0MCAXDTI2
MTAyMTE1MTg1MloYDzIxMjYwOTI3MTUxODUyWjAmMSQwIgYDVQQDDBt3aW5ybS1y
cyB0aHJvd2F3YXkgUlNBIHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCsWhd880i32fHv1h+0LpC5ujuDlC/XAGfcE1V/lIkavWXGcTgRzkT8xSZT
jkzrLsc+7J6GOwP20qaz1vDDnQRYzC/fn3iejSAz/qhLQtCbZ3akgDUrfFVKKisn
9CgDUudJKmIyNADZCm+ddCv9H89LAlQKDtBB/M5j1miBYRPYJF9dsZ3ONYIJKTe+
inhdrGPeZM6nF3WK1LIv6R9NvSarGdZniaTjvQq6uUTBPtYCi7783WnfiNQXEYni
w3QWT+S+y/2shUHnKR5YLa4utZT0x1xkoXM7RviHj89HqxGfYH0/pwgmA0HSwCm9
+DJsbiqr6LEDSICvPhhRaOwuKrWXAgMBAAGjaDBmMB0GA1UdDgQWBBRH7uJdyDUY
t7tm5jdxjiwXzDXkkzAfBgNVHSMEGDAWgBRH7uJdyDUYt7tm5jdxjiwXzDXkkzAP
BgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEB
CwUAA4IBAQAIzeuysqlSeFE1Bh03W+8gSXXXVMb1/aN4juqS5g/Wq1Knrxpm5MBE
MMmoLajlpJo+zjOrBaLlJx3/6kfrLBOO+NGJfbAV4py3ZNBf5bk1iXqKUiefSupJ
XY8VY4fpqPgb4ApF3Bj8jeTBjhACK05Zt75EI4PgWEZ7xz+f/qi2PQ9xMLelnM6b
Hs8f3gw+MUk5CeWjgrVDIudHKBweuAnbVUPrFe6u3DR0HinLKlh2+lPlTJ08BDno
Mq1O/Y2jXTS50fzrAiihDaqMXwoutGqr4vr3IMIoP3x9XfEiiemqiZk5x5yRPZt5
Oe5zjOD5k63fhMKGwCmyPVt+iXHEySCM
-----END CERTIFICATE-----
";

/// Key of [`RSA_CERT_PEM`], PKCS#1 encoding (`RSA PRIVATE KEY`).
pub(crate) const RSA_KEY_PKCS1_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArFoXfPNIt9nx79YftC6Qubo7g5Qv1wBn3BNVf5SJGr1lxnE4
Ec5E/MUmU45M6y7HPuyehjsD9tKms9bww50EWMwv3594no0gM/6oS0LQm2d2pIA1
K3xVSiorJ/QoA1LnSSpiMjQA2QpvnXQr/R/PSwJUCg7QQfzOY9ZogWET2CRfXbGd
zjWCCSk3vop4Xaxj3mTOpxd1itSyL+kfTb0mqxnWZ4mk470KurlEwT7WAou+/N1p
34jUFxGJ4sN0Fk/kvsv9rIVB5ykeWC2uLrWU9MdcZKFzO0b4h4/PR6sRn2B9P6cI
JgNB0sApvfgybG4qq+ixA0iArz4YUWjsLiq1lwIDAQABAoIBABMEayxkWRUVkqEu
H+1tE0G1ujS4jdbMD/8JOxk1YIjMy9rA9Ljc6QvNt9Q8aAxYla+XGEl4tY/vNRRe
684Jw0hbr2SeCgckofWwFw3G35G7htcmi7ddTrk85z96AfhBQOKihJdELwZueluw
oodEPUaU3oUFlsEmjfds2bcnk7L451pCZo5uf1n51grKrBAel7iW2MhBNU1m9nvF
cCxmInPrQumx1w2xQnNc4yIJxDl9aMnxzyhM7RMOCfmdutFJajLBkQ5MLZbUOxkL
8HZCr14frs91t+5GEEu2iMIJh0hE0u/yO3GpMInPUynpHJut4XBzmIMVf4duYoOC
BBg/G8ECgYEA3vfl2+5a9AMOQMh/dqj7lxjHg2KYnWFie5zJb0Ettq7btr6PsUER
LTEIdrz945FBY36derG3p6CiIYThf9ibIjkewEPf1vdGVFjv5SAsaNVnZRalxKir
7QLXu97Dpe5FqLWm453RbQHWJp0WXijgQVN4V/nX4GpswM03kxmRLBECgYEAxeKP
PTUWOcx6E3j0vohwbAlscEg5iz+NByhtK/XGQYljAZUHzXcv7nYaBid7U5xN71Q+
De1cHHxFvTNvVRBEFVT/BiPaT8KgJHYtYGEZRQQ+ZVzhV1f7IMp0Ru8i5UqUDKiX
3xoGwKAcskBVIBDdnqL1L/JzxFJkMG/agqf4DycCgYAcGvlxeKEkYwI37k4K4hAc
orX7fMEqDW2BkWjeykN95JqzdV/dgwssPCMJ/JawSc4JQZuOLLquuZPWT86w89fS
P4r9x1B+41qNJUzP//c5G7VVy74HhQ9u583T06er0dYcBxHLXUhZykJ5SZHZOqPR
+DiSNl8c3a1pvDSGKVHgUQKBgGz7CkH+Q6BPUYf53Gg2ghut0O/Bhxd+R3ACvqUw
NSCQxlrvtZ1dn6Mnnct34P66HV3KOma3Kzxw4IODmTPywlwxNEYwZqH4oPOTtgfX
UfBlluuCDIRq6t4zQXhzaPd4bDLQgtuW3NMnGsa8kWUYhMVCH+BpGYKskYrvfxrn
4MCPAoGAKlQi8ViLUgm6COnvt9Wg8231UBPUa7ti5eyXpNAeZE1mImSsXorlL+eL
y+1OqhmsxYpS3Kkly7Rb2+R/N7nPg5g62B6UMFC9NWMnwSIdKBYhABD+N1OGK+zx
QqWuUTzB57v+yrv97Faoucjjd5yOzBXq4JF10QtmQDeOrVtZNqI=
-----END RSA PRIVATE KEY-----
";

/// Key of [`EC_CERT_PEM`], encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`, passphrase `throwaway`).
pub(crate) const EC_KEY_PKCS8_ENCRYPTED_PEM: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCmSHJuPZv3v+Re654n
PvuoAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQfmd5MaxzV2RcuawG
AVM0gASBkECth2CFURk6OnOn7lWU+BdfT/KjHP+cCrk8W3QSws9x0p/VK7tvt69z
oEOYLCWLT+Wh+78NGHifLtRnzLxlRwlLFOa01sHl5npYLIX47Y2JbmuDYGlTPxgb
z8LLYZDejJ+5dQnHucOoIZ16a+KEas/i0lif51ITJaDvZideB74GysPxZ3/Yw8Bt
TZJnQuZboA==
-----END ENCRYPTED PRIVATE KEY-----
";

/// Key of [`EC_CERT_PEM`], legacy OpenSSL encryption (`Proc-Type: 4,ENCRYPTED`, passphrase `throwaway`).
pub(crate) const EC_KEY_SEC1_LEGACY_ENCRYPTED_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,651758622B52D18F47BBA1E64091940C

fiHa7zwQUccr7SMfenx/jxVmJ2aEI5NXs+4onrvwjnTpQZHHq9ZrCqqDU77VSDvP
c10yteV0lqpywlvVbVtCXtutGCzeBKjbK5RQXrAbXwJELCgbG201IwrOcAd+VGv7
ossscMeEp9LLtzWBEfaSSeVuhGBbT9OgD/WW8jQbVOc=
-----END EC PRIVATE KEY-----
";

// --- Channel binding (RFC 5929 tls-server-end-point) fixtures ---
//
// Self-signed throwaway certificates, one per signature algorithm, for the
// CBT hash selection. Generated once with OpenSSL 3.5.9 (Fedora; SHA-1
// signing needs a config with `rh-allow-sha1-signatures = yes`):
//
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes \
//       -keyout ec384.key -out ec384-sha384.pem -days 36500 -subj /CN=winrm-rs-cbt-ec384
//   openssl req -x509 -newkey rsa:2048 -sha512 -nodes -keyout rsa.key \
//       -out rsa-sha512.pem -days 36500 -subj /CN=winrm-rs-cbt-rsa-sha512
//   openssl req -x509 -key rsa.key -sha384 -out rsa-sha384.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-rsa-sha384
//   openssl req -x509 -key ec384.key -sha512 -out ec384-sha512.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-ec-sha512
//   openssl req -x509 -key rsa.key -sha384 -sigopt rsa_padding_mode:pss \
//       -sigopt rsa_pss_saltlen:48 -out rsa-pss-sha384.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-pss384
//   OPENSSL_CONF=sha1.cnf openssl req -x509 -key rsa.key -sha1 -out rsa-sha1.pem \
//       -days 36500 -subj /CN=winrm-rs-cbt-rsa-sha1   (and -key ec384.key -> ec-sha1.pem)
//   openssl req -x509 -key rsa.key -md5 -out rsa-md5.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-rsa-md5
//   openssl genpkey -algorithm ed25519 -out ed.key
//   openssl req -x509 -key ed.key -out ed25519.pem -days 36500 -subj /CN=winrm-rs-cbt-ed25519
//
// The expected CBT values in the tests were computed independently with
// Python `cryptography` 48.0 the way pypsrp does (`signature_hash_algorithm`,
// MD5/SHA-1 upgraded to SHA-256), then the gss_channel_bindings struct and MD5.

/// P-384 key, ecdsa-with-SHA384.
pub(crate) const CBT_EC384_SHA384_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBzjCCAVSgAwIBAgIUXMRXi/j9EAIdPd/T87P08kG4+Z4wCgYIKoZIzj0EAwMw
HTEbMBkGA1UEAwwSd2lucm0tcnMtY2J0LWVjMzg0MCAXDTI2MTAyMTIxMzU1NVoY
DzIxMjYwOTI3MjEzNTU1WjAdMRswGQYDVQQDDBJ3aW5ybS1ycy1jYnQtZWMzODQw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ/vZYdBhHkYsTmvh1iI8vn7F6ITilh3YBI
qOTDB5Sy1nZA0yh1J1rmF9CJ7ePlF/6xnmKNj9EkgFzMBgVTODM7/h7z9c06DUWI
BSuN0Vs19jMvQ1kXmrF0LAxVF012co+jUzBRMB0GA1UdDgQWBBQUca820zU3M10z
o9DIUgAu03ZiPDAfBgNVHSMEGDAWgBQUca820zU3M10zo9DIUgAu03ZiPDAPBgNV
HRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2gAMGUCMQDwBHWPkx0tLMSsxzqvYqNj
3Y9hM6TMACgGj+SrQzkLtjoc8OotnEbmSjX3eR0GnsECMGCrnLmKOVoimqBe2+Fp
wYRtiL/NQSRcx0/7vOmwbcrntaDkcwFrXVbFdqCvgVOhAw==
-----END CERTIFICATE-----
";

/// The P-384 key of the ECDSA fixtures (PKCS#8).
pub(crate) const CBT_EC384_SHA384_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAdFdISMYjfKd6TRnX3
Yv0UsLwjDNCo4YacPc3sGRseevTRulKyEQVqa6zZX7MdahuhZANiAAQ/vZYdBhHk
YsTmvh1iI8vn7F6ITilh3YBIqOTDB5Sy1nZA0yh1J1rmF9CJ7ePlF/6xnmKNj9Ek
gFzMBgVTODM7/h7z9c06DUWIBSuN0Vs19jMvQ1kXmrF0LAxVF012co8=
-----END PRIVATE KEY-----
";

/// P-384 key, ecdsa-with-SHA512.
pub(crate) const CBT_EC_SHA512_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB1zCCAVygAwIBAgIUE4g0sXKxXS4NCM3VqvGInIlPhNEwCgYIKoZIzj0EAwQw
ITEfMB0GA1UEAwwWd2lucm0tcnMtY2J0LWVjLXNoYTUxMjAgFw0yNjEwMjEyMTM1
NTVaGA8yMTI2MDkyNzIxMzU1NVowITEfMB0GA1UEAwwWd2lucm0tcnMtY2J0LWVj
LXNoYTUxMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABD+9lh0GEeRixOa+HWIjy+fs
XohOKWHdgEio5MMHlLLWdkDTKHUnWuYX0Int4+UX/rGeYo2P0SSAXMwGBVM4Mzv+
HvP1zToNRYgFK43RWzX2My9DWReasXQsDFUXTXZyj6NTMFEwHQYDVR0OBBYEFBRx
rzbTNTczXTOj0MhSAC7TdmI8MB8GA1UdIwQYMBaAFBRxrzbTNTczXTOj0MhSAC7T
dmI8MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwQDaQAwZgIxAM33Y7tca+Dv
SlSs23Pd2jxU6VaO7rUq8EmWT0hYuEVy+FquVys+Spe844dPDDJQGwIxAPB4GbHz
gYjHM9fomSKngvkqwL5t5QCduR6/Iud+zCmJQ6VBC097urghjDZc+DGt7Q==
-----END CERTIFICATE-----
";

/// P-384 key, ecdsa-with-SHA1.
pub(crate) const CBT_EC_SHA1_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBnjCCASWgAwIBAgIUWgfFctPlTkVsruFFQ56/6uikwswwCQYHKoZIzj0EATAf
MR0wGwYDVQQDDBR3aW5ybS1ycy1jYnQtZWMtc2hhMTAgFw0yNjEwMjEyMTM2MTFa
GA8yMTI2MDkyNzIxMzYxMVowHzEdMBsGA1UEAwwUd2lucm0tcnMtY2J0LWVjLXNo
YTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ/vZYdBhHkYsTmvh1iI8vn7F6ITilh
3YBIqOTDB5Sy1nZA0yh1J1rmF9CJ7ePlF/6xnmKNj9EkgFzMBgVTODM7/h7z9c06
DUWIBSuN0Vs19jMvQ1kXmrF0LAxVF012co+jITAfMB0GA1UdDgQWBBQUca820zU3
M10zo9DIUgAu03ZiPDAJBgcqhkjOPQQBA2gAMGUCMGTOPSqNlLU+wyzQFTWFbelf
pku8aEFfrYkB7tbjMJaifYsTDtFlHkpXhmz3l6eglAIxAMV3GUGD2kJ9q8JszwiA
jw9cOUDmRdwnzTUlfied4pAWeG7ryRlgxGG+HN8eGoZhZQ==
-----END CERTIFICATE-----
";

/// RSA-2048, sha384WithRSAEncryption.
pub(crate) const CBT_RSA_SHA384_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUBk+TbFcJFRYeGEPnq/+5HUe14iYwDQYJKoZIhvcNAQEM
BQAwIjEgMB4GA1UEAwwXd2lucm0tcnMtY2J0LXJzYS1zaGEzODQwIBcNMjYxMDIx
MjEzNTU1WhgPMjEyNjA5MjcyMTM1NTVaMCIxIDAeBgNVBAMMF3dpbnJtLXJzLWNi
dC1yc2Etc2hhMzg0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq775
lD7iisGC03+h3gvGCC9Pby1Phdv9766Dc6wAJHZ6zsKRe0s2i6WwCGamaImaHZnU
VQU7kJBERmhofd0HjaZRhZmCwO/LshSwOVAmAaC/IJvBgO2t+AJXlXrb1YVdqxhk
8onMfnupGxUWRAeeQzcM/KFLbTl8stYwKlfWpvhgpX5/5W4AO7pe5XUEIXHyZWqP
u8b3rOnNNDgyaFWb13JcWslulwfWG+dj1nY94eP+bcPAX8jtHojIfHif5//Rgykv
LvGPGqjqwADdmORNHvCRIyX+M7XVanTfuZAD3WGV+aOp38DzP+BLC6wTbbOU6dcZ
u0pL75+FBlwdxjSUJQIDAQABo1MwUTAdBgNVHQ4EFgQUai1sfX0ky3ffeOUK8Zt6
GiS2s1MwHwYDVR0jBBgwFoAUai1sfX0ky3ffeOUK8Zt6GiS2s1MwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOCAQEAMjtJd/OxpIULGlZiE7abzL2pi9s2
2/VCpOztsFkKtQi4lnlTV7xtHjJkfgKsTMwZ9pTFoF6/Lqb0Wr7sbtdghnnVhhzP
ICDpGo3PUf8jO3/GxxoAVfL+FJsNNVjcncClN4OoD/JsmB/+D6vISIMpY1vo/bN+
7Ef/xDKFmOtVOOz+pAg91fEkFj8ityXVyTjFu9Z7IX/TWbTzhuqeaLDyMRHSmfq2
IiuP3KWdcuKScutVaycZgaibMpjZJO1zg10Yta5E3K8/3rNIbGZDeAjitdNYv+Bb
TPmv28p+e5M4hPJ+4A+eXRzidWaYoJGiGld1QxCEpuQhJgbO28GdfiTbCA==
-----END CERTIFICATE-----
";

/// RSA-2048, sha512WithRSAEncryption.
pub(crate) const CBT_RSA_SHA512_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUY5KdtjDPK0yATTjDvRxwXPVtOwQwDQYJKoZIhvcNAQEN
BQAwIjEgMB4GA1UEAwwXd2lucm0tcnMtY2J0LXJzYS1zaGE1MTIwIBcNMjYxMDIx
MjEzNTU1WhgPMjEyNjA5MjcyMTM1NTVaMCIxIDAeBgNVBAMMF3dpbnJtLXJzLWNi
dC1yc2Etc2hhNTEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq775
lD7iisGC03+h3gvGCC9Pby1Phdv9766Dc6wAJHZ6zsKRe0s2i6WwCGamaImaHZnU
VQU7kJBERmhofd0HjaZRhZmCwO/LshSwOVAmAaC/IJvBgO2t+AJXlXrb1YVdqxhk
8onMfnupGxUWRAeeQzcM/KFLbTl8stYwKlfWpvhgpX5/5W4AO7pe5XUEIXHyZWqP
u8b3rOnNNDgyaFWb13JcWslulwfWG+dj1nY94eP+bcPAX8jtHojIfHif5//Rgykv
LvGPGqjqwADdmORNHvCRIyX+M7XVanTfuZAD3WGV+aOp38DzP+BLC6wTbbOU6dcZ
u0pL75+FBlwdxjSUJQIDAQABo1MwUTAdBgNVHQ4EFgQUai1sfX0ky3ffeOUK8Zt6
GiS2s1MwHwYDVR0jBBgwFoAUai1sfX0ky3ffeOUK8Zt6GiS2s1MwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAL1CDRKx4s6XOqZbUCzv3Mk/tCplN
pPv6CmyROfqzktDkn59UrG2DpFrs7+YVhBCITp49a/HxsaoGqHUb1aSyrlrkmByT
PbKbNmCZkHwFOuC447gU0Ielh/c6xpGTba4SMJALTNjnG8Guuz21FqZ+AZZF7TsL
6VrEZuVGNgE5m4QcTgyRcQEfxeCI3n3A2O35f0GBjuV+gxdd1wGb3kG6rXb2dg5S
QMrxln80pnQelfHuAzuRA+1DDRcAs91/1lJW8nAiN35leuhPKII7CIAUSZPuzjSc
c3GTo/4wh7uuy/SH2rKWbI/7QIbW1NwPEAcJ4+PbpQQWsIqTErEM1QkVYA==
-----END CERTIFICATE-----
";

/// RSA-2048, sha1WithRSAEncryption.
pub(crate) const CBT_RSA_SHA1_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIC8TCCAdmgAwIBAgIUG46kftdTvGwHoMBGAF0qVqjtBfAwDQYJKoZIhvcNAQEF
BQAwIDEeMBwGA1UEAwwVd2lucm0tcnMtY2J0LXJzYS1zaGExMCAXDTI2MTAyMTIx
MzYwMloYDzIxMjYwOTI3MjEzNjAyWjAgMR4wHAYDVQQDDBV3aW5ybS1ycy1jYnQt
cnNhLXNoYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjITAfMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzANBgkqhkiG9w0BAQUFAAOCAQEAXQwgPffZAoaaKt0UKe+Og3tw6HPGvE20Bs+H
J8pjlqZadskaF9tSLo/n37lUreCEnzcSvqsBk92jxpCZT8V1YL1xMvUGhHWBQOe8
fq7gM0U1Xiq9TTb8+q8y03o31qV82fCJi2hxFU146VPdmUKfmMWl6B3EHOxaji4T
XtL+8QLnG6oryb847n7wQ1oI9kme0aZjfoMfZV91SmzXCldWCeysoZkCGLuAuOZO
jTWEuWocfwUyrnfYmoLlrBdvUjH7iLeMr6plwmCBLUTwHijQiAB+iQBNNKwTtEcX
TByjA3UVwRRWAmWGvQymfxU/DUiwdRocblYwUWHElt1Kd2QjHg==
-----END CERTIFICATE-----
";

/// RSA-2048, md5WithRSAEncryption.
pub(crate) const CBT_RSA_MD5_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUDbNu4F9Xv+FvzGNLXAV9wsVukA8wDQYJKoZIhvcNAQEE
BQAwHzEdMBsGA1UEAwwUd2lucm0tcnMtY2J0LXJzYS1tZDUwIBcNMjYxMDIxMjEz
NTU1WhgPMjEyNjA5MjcyMTM1NTVaMB8xHTAbBgNVBAMMFHdpbnJtLXJzLWNidC1y
c2EtbWQ1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq775lD7iisGC
03+h3gvGCC9Pby1Phdv9766Dc6wAJHZ6zsKRe0s2i6WwCGamaImaHZnUVQU7kJBE
Rmhofd0HjaZRhZmCwO/LshSwOVAmAaC/IJvBgO2t+AJXlXrb1YVdqxhk8onMfnup
GxUWRAeeQzcM/KFLbTl8stYwKlfWpvhgpX5/5W4AO7pe5XUEIXHyZWqPu8b3rOnN
NDgyaFWb13JcWslulwfWG+dj1nY94eP+bcPAX8jtHojIfHif5//RgykvLvGPGqjq
wADdmORNHvCRIyX+M7XVanTfuZAD3WGV+aOp38DzP+BLC6wTbbOU6dcZu0pL75+F
BlwdxjSUJQIDAQABo1MwUTAdBgNVHQ4EFgQUai1sfX0ky3ffeOUK8Zt6GiS2s1Mw
HwYDVR0jBBgwFoAUai1sfX0ky3ffeOUK8Zt6GiS2s1MwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQQFAAOCAQEALeNDYtWjzDAbPHQUAbWdTFrV2ZqWxLK5g5yp
9zTXB/mmNjuBU+2DfNWAsmiU6MBOrgthUj4pLX9eFXPlfEB4gRBMCmdHTfiSoDWP
kfHLGbxXlrdyvNuH4mMDU41vmADHJ2TS78h91YCqPBEssUQClUWcokh9QazqyEqc
ldgFmN6v8/dswYnrPYR90SV43+MpgrhRxE3tGO8RI3dIQmkpr03lik3BMQAp7oCm
g67tUX2otjG39s+ZDWWDnQwr2SUPAWH0jExP8YU2n8IyGis+pVsSL/vpZs2qW5JK
ytVgU7tZG8YMxUnKnAq6rM9428xsf4h0m31drV22iumBmsRg/A==
-----END CERTIFICATE-----
";

/// RSA-2048, RSASSA-PSS with SHA-384.
pub(crate) const CBT_RSA_PSS_SHA384_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDhzCCAjugAwIBAgIUM89+362Ttw+NpHeUyfNQFB+5iL8wQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIF
AKIDAgEwMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNidC1wc3MzODQwIBcNMjYxMDIx
MjEzNTU1WhgPMjEyNjA5MjcyMTM1NTVaMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNi
dC1wc3MzODQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjUzBRMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzAfBgNVHSMEGDAWgBRqLWx9fSTLd9945Qrxm3oaJLazUzAPBgNVHRMBAf8EBTAD
AQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B
AQgwDQYJYIZIAWUDBAICBQCiAwIBMAOCAQEAXMxmoiAiwKMQOiezARFWt3jqBugG
iDKxETpqGWatA5GLSviS3FCKeL40m9DZAvd8FobUL2JaCdMyOQmXWaWwNMDWj5Bt
K1IvOU+OMRLT/SGSceRIEQhhcHYRQpNWkIKOsmJvv8DpQK6ZPagIV2XABzXyq5TO
f7FU2P/NZwVOrtMaCfaClfDOocns1DS5g5vjh+ELEZ4kZTUUkd6P8nBrz97xD0IJ
DKdKx7QN3CPatB+qkf5T7HCJRzcqanx8U7r3TPeDQLGL9QlFgHrDeL+B15NSxbfy
HaRstU89hUpT5gV7BrqokoJCGiWeo+6Q644MhFSz9JPJTGhm18slWx/f0Q==
-----END CERTIFICATE-----
";

/// Ed25519 (no hash in the signature algorithm).
pub(crate) const CBT_ED25519_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBVTCCAQegAwIBAgIUESB/B8ObJlWJeU3jyGOoaZlhX7gwBQYDK2VwMB8xHTAb
BgNVBAMMFHdpbnJtLXJzLWNidC1lZDI1NTE5MCAXDTI2MTAyMTIxMzU1NVoYDzIx
MjYwOTI3MjEzNTU1WjAfMR0wGwYDVQQDDBR3aW5ybS1ycy1jYnQtZWQyNTUxOTAq
MAUGAytlcAMhANShMiQcj/eDzxU2xyt3N9a9zb78IjGqU5PqNLdm8yPRo1MwUTAd
BgNVHQ4EFgQUXu+BPBomwm9IXmjd40TIXS0HsPIwHwYDVR0jBBgwFoAUXu+BPBom
wm9IXmjd40TIXS0HsPIwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQC+5xXjDQO1
fOW5G6VNKpguH3Ur8UiVvTLEXGjMlFMsuG0YBlFmb7O7HKv+32KE1A+544xCK5sM
vYOXB6YzzhED
-----END CERTIFICATE-----
";

// More channel binding fixtures (same key files as above):
//
//   openssl req -x509 -key rsa.key -sha224 -out rsa-sha224.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-rsa-sha224
//   openssl req -x509 -key ec384.key -sha224 -out ec-sha224.pem -days 36500 \
//       -subj /CN=winrm-rs-cbt-ec-sha224
//   openssl req -x509 -key rsa.key -sha256 -sigopt rsa_padding_mode:pss \
//       -sigopt rsa_pss_saltlen:32 -out rsa-pss-sha256.pem -days 36500 -subj /CN=winrm-rs-cbt-pss256
//   openssl req -x509 -key rsa.key -sha512 -sigopt rsa_padding_mode:pss \
//       -sigopt rsa_pss_saltlen:64 -out rsa-pss-sha512.pem -days 36500 -subj /CN=winrm-rs-cbt-pss512
//   OPENSSL_CONF=sha1.cnf openssl req -x509 -key rsa.key -sha1 -sigopt rsa_padding_mode:pss \
//       -sigopt rsa_pss_saltlen:20 -out rsa-pss-sha1.pem -days 36500 -subj /CN=winrm-rs-cbt-pss-sha1
//   (rsa-pss-absent: rsa-pss-sha1 with the outer `30 0D 06 09 <rsassaPss> 30 00` rewritten
//   to `30 0B 06 09 <rsassaPss>` and the outer SEQUENCE length reduced by 2, in Python.)

/// RSA-2048, sha224WithRSAEncryption.
pub(crate) const CBT_RSA_SHA224_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUfNZmFpfhCeX5amPpB3ubcSHbOjMwDQYJKoZIhvcNAQEO
BQAwIjEgMB4GA1UEAwwXd2lucm0tcnMtY2J0LXJzYS1zaGEyMjQwIBcNMjYxMDIx
MjIzNTIyWhgPMjEyNjA5MjcyMjM1MjJaMCIxIDAeBgNVBAMMF3dpbnJtLXJzLWNi
dC1yc2Etc2hhMjI0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq775
lD7iisGC03+h3gvGCC9Pby1Phdv9766Dc6wAJHZ6zsKRe0s2i6WwCGamaImaHZnU
VQU7kJBERmhofd0HjaZRhZmCwO/LshSwOVAmAaC/IJvBgO2t+AJXlXrb1YVdqxhk
8onMfnupGxUWRAeeQzcM/KFLbTl8stYwKlfWpvhgpX5/5W4AO7pe5XUEIXHyZWqP
u8b3rOnNNDgyaFWb13JcWslulwfWG+dj1nY94eP+bcPAX8jtHojIfHif5//Rgykv
LvGPGqjqwADdmORNHvCRIyX+M7XVanTfuZAD3WGV+aOp38DzP+BLC6wTbbOU6dcZ
u0pL75+FBlwdxjSUJQIDAQABo1MwUTAdBgNVHQ4EFgQUai1sfX0ky3ffeOUK8Zt6
GiS2s1MwHwYDVR0jBBgwFoAUai1sfX0ky3ffeOUK8Zt6GiS2s1MwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQ4FAAOCAQEAcIW68pElJOl7qnAQzDcAl1vFGzE8
C9hjUXrS7mGvrA7n4uzHSYkmaO9DA8XYpZKveFLQ1baO/pZ2wPi+GogbtqDwRTPO
NUlQe0v5XdOVYraVP9yLup+az2rR3Hf/0W1XImjNzwhPabRf7mW9ewMbvakMJ/qL
2YCyQPtJdzR2u4/dc7gDbrRkgFFqb4Mx0gJdL7D82OOpQ4nQygH7j+zFWdR25y5w
fO09r9/4PkljLo4orncok6ot1TzxMNDAQ4WHs842t/QmXceyjyx5GSDgGo8AJkVC
Tujm4SeQIWJ9dnqz0rX+vxZLoAhfeovJZktaOW/gI9Q08SzbS7h0HrI+oQ==
-----END CERTIFICATE-----
";

/// P-384 key, ecdsa-with-SHA224.
pub(crate) const CBT_EC_SHA224_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB1jCCAVygAwIBAgIUZRDP7wmrx0qu6pqh0hPPOzUXFnIwCgYIKoZIzj0EAwEw
ITEfMB0GA1UEAwwWd2lucm0tcnMtY2J0LWVjLXNoYTIyNDAgFw0yNjEwMjEyMjM1
MjJaGA8yMTI2MDkyNzIyMzUyMlowITEfMB0GA1UEAwwWd2lucm0tcnMtY2J0LWVj
LXNoYTIyNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABD+9lh0GEeRixOa+HWIjy+fs
XohOKWHdgEio5MMHlLLWdkDTKHUnWuYX0Int4+UX/rGeYo2P0SSAXMwGBVM4Mzv+
HvP1zToNRYgFK43RWzX2My9DWReasXQsDFUXTXZyj6NTMFEwHQYDVR0OBBYEFBRx
rzbTNTczXTOj0MhSAC7TdmI8MB8GA1UdIwQYMBaAFBRxrzbTNTczXTOj0MhSAC7T
dmI8MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwEDaAAwZQIxAIYn8hlbl/I8
FUphAqvODmpFh30UAzDWmVVd1HhRRex4/3w1iJrOM9qqaaHtj0tF5wIwT8rls4iN
fwU/KH7jO9LXYd9+pX4WoM/unl3NycPtzzGv0oIEpXC0vbI03rzldiyf
-----END CERTIFICATE-----
";

/// RSA-2048, RSASSA-PSS with SHA-256.
pub(crate) const CBT_RSA_PSS_SHA256_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDhzCCAjugAwIBAgIUe2zXQmLfuib+t6IFIn20XOBjnJgwQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNidC1wc3MyNTYwIBcNMjYxMDIx
MjIzNTIyWhgPMjEyNjA5MjcyMjM1MjJaMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNi
dC1wc3MyNTYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjUzBRMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzAfBgNVHSMEGDAWgBRqLWx9fSTLd9945Qrxm3oaJLazUzAPBgNVHRMBAf8EBTAD
AQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0B
AQgwDQYJYIZIAWUDBAIBBQCiAwIBIAOCAQEAj+87w5IRkF9+/tnNvGdPI5Eg/DHV
Eqj2ugyw+b2FC9/r9ikJeEiT42ETv7Fjw12TilgHitkJEZ1KyDLt7pBnyXnK9A/S
Eb9d4Ma5mBHuq212bskRAduxPMdaUQcCJ/bOIJ/sAeT+9km7HI0f8NdqweKSKY1L
Eax8vJsl18BLewxDzlMDJejtkNNDqRFtD0b2tJjCa7j01o2k5nIlK991r+qCI3M3
wG1HshyDVPZ5Tc8Vayq+rm6QEaB4cXhiweS9FSBJPKfLn74ahZM1OfLOnjYGnSsU
jqDx0Sg37Hp10B8PcR2Hv5SK8zyVxxfBbcm6DsINPpO+yB/lQie89fYvMg==
-----END CERTIFICATE-----
";

/// RSA-2048, RSASSA-PSS with SHA-512.
pub(crate) const CBT_RSA_PSS_SHA512_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDhzCCAjugAwIBAgIUC4AwKGz0pxmJmJKYM3eUD+4mhI0wQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMF
AKIDAgFAMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNidC1wc3M1MTIwIBcNMjYxMDIx
MjIzNTIyWhgPMjEyNjA5MjcyMjM1MjJaMB4xHDAaBgNVBAMME3dpbnJtLXJzLWNi
dC1wc3M1MTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjUzBRMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzAfBgNVHSMEGDAWgBRqLWx9fSTLd9945Qrxm3oaJLazUzAPBgNVHRMBAf8EBTAD
AQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAIDBQChHDAaBgkqhkiG9w0B
AQgwDQYJYIZIAWUDBAIDBQCiAwIBQAOCAQEAB6/Sd8ul52mRNOMNgu78RB/qPDFk
MV4FQc6cmB0KHxxEvnXMTmzCgO+KfCEv36+khO/hFJmipn7iIvUP0CWX1qhahrVK
T0krVa01LeHWobTRWAy6oi7MpzWEbz0nFRbwJ3r1nqum180whszbmSQFGE7Z58BS
+JeeP1EOd+stfnd/78Fz4MoWDC5veafn1Qbm1+Ho87zp5DI1Zvru/V1M/WjOG0pu
rg4QcJPkEgDvY3giPuXUBZ+LQvatQX3cb8bj3UqmSercUYeGBjIbTDLIWaCu7V/h
NJP1oRcYDENst5udMUzRrva52PsGTr9hN2amHv/6I7Py2/VF03e0FxK6mA==
-----END CERTIFICATE-----
";

/// RSA-2048, RSASSA-PSS with all-default (empty) parameters: SHA-1.
pub(crate) const CBT_RSA_PSS_DEFAULTS_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIC8TCCAdmgAwIBAgIULe4wWF8YLEqIMJi5WlmI2LpdICcwDQYJKoZIhvcNAQEK
MAAwIDEeMBwGA1UEAwwVd2lucm0tcnMtY2J0LXBzcy1zaGExMCAXDTI2MTAyMTIy
MzUyMloYDzIxMjYwOTI3MjIzNTIyWjAgMR4wHAYDVQQDDBV3aW5ybS1ycy1jYnQt
cHNzLXNoYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjITAfMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzANBgkqhkiG9w0BAQowAAOCAQEAA5yJcgxklBKTGr60e+eVlDYkah9l7LLjnfuj
zXQUxR1eHNISm3BDsST0/CkafYhSnmBqBpNU7PbuvS4IJPauf8FmRZjvGKRiy5HM
YXHY2D3oD2v4iyEPsgYGoSJ+K7qTMv/s9UltNn1DCLom0YP88AjE8QgonuLbD4Em
fj/09ylYBxB/LvzUiqrWaDlHAXYlNyQ0xAXO/0wLDZOcpHTlAdwGNbTLqvBadHN0
8U3+1E+j21LFHhnDfc7jqT2aMcwthEkVMaOAyXBZC2dmmLbd2nK7vVHgmanmFGb3
VwuXhqMjpjxPwRJh5Baw707VL/uwMKk2Y0svvYC7BjfrxuLA7Q==
-----END CERTIFICATE-----
";

/// The RSASSA-PSS defaults certificate with its outer signatureAlgorithm parameters removed (crafted: OID only; the signature no longer verifies, which the CBT does not need).
pub(crate) const CBT_RSA_PSS_ABSENT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIC7zCCAdmgAwIBAgIULe4wWF8YLEqIMJi5WlmI2LpdICcwDQYJKoZIhvcNAQEK
MAAwIDEeMBwGA1UEAwwVd2lucm0tcnMtY2J0LXBzcy1zaGExMCAXDTI2MTAyMTIy
MzUyMloYDzIxMjYwOTI3MjIzNTIyWjAgMR4wHAYDVQQDDBV3aW5ybS1ycy1jYnQt
cHNzLXNoYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrvvmUPuKK
wYLTf6HeC8YIL09vLU+F2/3vroNzrAAkdnrOwpF7SzaLpbAIZqZoiZodmdRVBTuQ
kERGaGh93QeNplGFmYLA78uyFLA5UCYBoL8gm8GA7a34AleVetvVhV2rGGTyicx+
e6kbFRZEB55DNwz8oUttOXyy1jAqV9am+GClfn/lbgA7ul7ldQQhcfJlao+7xves
6c00ODJoVZvXclxayW6XB9Yb52PWdj3h4/5tw8BfyO0eiMh8eJ/n/9GDKS8u8Y8a
qOrAAN2Y5E0e8JEjJf4ztdVqdN+5kAPdYZX5o6nfwPM/4EsLrBNts5Tp1xm7Skvv
n4UGXB3GNJQlAgMBAAGjITAfMB0GA1UdDgQWBBRqLWx9fSTLd9945Qrxm3oaJLaz
UzALBgkqhkiG9w0BAQoDggEBAAOciXIMZJQSkxq+tHvnlZQ2JGofZeyy4537o810
FMUdXhzSEptwQ7Ek9PwpGn2IUp5gagaTVOz27r0uCCT2rn/BZkWY7xikYsuRzGFx
2Ng96A9r+IshD7IGBqEifiu6kzL/7PVJbTZ9Qwi6JtGD/PAIxPEIKJ7i2w+BJn4/
9PcpWAcQfy781Iqq1mg5RwF2JTckNMQFzv9MCw2TnKR05QHcBjW0y6rwWnRzdPFN
/tRPo9tSxR4Zw33O46k9mjHMLYRJFTGjgMlwWQtnZpi23dpyu71R4Jmp5hRm91cL
l4ajI6Y8T8ESYeQWsO9O1S/7sDCpNmNLL72AuwY368biwO0=
-----END CERTIFICATE-----
";

/// Throwaway; signs a handshake with someone else's certificate.
pub(crate) const IMPOSTOR_EC_KEY_PKCS8_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgo3vpmJqQd+dRjJ1A
e8wB5ZKXW454BkvTzdUxB3SxLTihRANCAASMHHL9ze51gTZXP39HeGt0VYT5EoIL
TZkzaJG8kyjjXD9Hm+4XvQoYWD7qDvK1xYymIr+F28TE4IV/nKG5Axfi
-----END PRIVATE KEY-----
";

/// Throwaway P-256 CA (`CN=winrm-rs throwaway test CA`, `CA:TRUE`); it issued [`CA_LEAF_PEM`].
pub(crate) const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUUFwHMwwgXImKMIMdRG/DbhF3a80wCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwad2lucm0tcnMgdGhyb3dhd2F5IHRlc3QgQ0EwIBcNMjYxMDI1
MDA1NTE5WhgPMjEyNjEwMDEwMDU1MTlaMCUxIzAhBgNVBAMMGndpbnJtLXJzIHRo
cm93YXdheSB0ZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4huGQcE4
Z73m9e946pA4Y98uJIdolSHqlz7mDSft5pFjbKLeIUqpIYll06deGjUU4CPQMk23
mjTt43hlzf9/QKNTMFEwHQYDVR0OBBYEFPTwETCVzdw1CASJRkzrMAZ8W1LhMB8G
A1UdIwQYMBaAFPTwETCVzdw1CASJRkzrMAZ8W1LhMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIgOKOHuw8q3VCCQw47qbYXlUEdUWyS/L5SA2m3a0Ld
Q9gCIQCRJbfABdEhBBjXR4n0iHsQjlFXRtTYunYfeny23AHKOA==
-----END CERTIFICATE-----
";

/// P-256 listener certificate issued by [`TEST_CA_PEM`]: `CA:FALSE`, `serverAuth`, SAN `DNS:localhost`.
pub(crate) const CA_LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB0DCCAXWgAwIBAgIBAjAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBp3aW5ybS1y
cyB0aHJvd2F3YXkgdGVzdCBDQTAgFw0yNjEwMjUwMDU1MTlaGA8yMTI2MTAwMTAw
NTUxOVowLDEqMCgGA1UEAwwhd2lucm0tcnMgdGhyb3dhd2F5IENBLWlzc3VlZCBs
ZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv+C/7q8/0QRGgELNJ87xUEu1
UObYe0fI6m6Ay54jrct+NJbE2Od/4hq/RQBMQY08G1HyDZ9ghd8JTvV2Lv4HT6OB
jDCBiTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwHQYDVR0OBBYEFG9P1EjVHlKq
Ee6XqitUghpW1dMbMB8GA1UdIwQYMBaAFPTwETCVzdw1CASJRkzrMAZ8W1LhMAoG
CCqGSM49BAMCA0kAMEYCIQD1tBuoonZiLYdN5VA4TAgyvol/hNgAJbHCvG7gQx5l
UgIhAJ8caRvuzb58cSw83SpUQuefW+XRhfpbo2aHA+WAsBda
-----END CERTIFICATE-----
";

/// Key of [`CA_LEAF_PEM`], PKCS#8 (`PRIVATE KEY`).
pub(crate) const CA_LEAF_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsXq/yism2esy250x
kiHHs5JOMZcMVs+g7T4A4oRkkBihRANCAAS/4L/urz/RBEaAQs0nzvFQS7VQ5th7
R8jqboDLniOty340lsTY53/iGr9FAExBjTwbUfINn2CF3wlO9XYu/gdP
-----END PRIVATE KEY-----
";

/// Self-signed P-256 certificate that is not a CA: `CA:FALSE`, `serverAuth`, SAN `DNS:localhost`.
pub(crate) const NON_CA_SELF_SIGNED_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBuzCCAWGgAwIBAgIBAzAKBggqhkjOPQQDAjAwMS4wLAYDVQQDDCV3aW5ybS1y
cyB0aHJvd2F3YXkgbm9uLUNBIHNlbGYtc2lnbmVkMCAXDTI2MTAyNTAwNTUxOVoY
DzIxMjYxMDAxMDA1NTE5WjAwMS4wLAYDVQQDDCV3aW5ybS1ycyB0aHJvd2F3YXkg
bm9uLUNBIHNlbGYtc2lnbmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfvSH
H5kZbJ9Mx7bahe8es5czIx0+e7mKLZRs3o0wOwY520JhPDy69fvipIffEn/C5J5z
y9XbsBgy/j1uU7A3NaNqMGgwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4Aw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0GA1Ud
DgQWBBRRWfhbsNNIxoQcgrw0Ppv0nRRlFjAKBggqhkjOPQQDAgNIADBFAiBMDUge
67lJPpN70bxW1XJXIDAQXn9EADnLmQPb3qB2jAIhAMkLcX/ye+I58dBWGhf6szTA
sBIpF5KMbj5lLMqNmt32
-----END CERTIFICATE-----
";

/// Key of [`NON_CA_SELF_SIGNED_PEM`], PKCS#8 (`PRIVATE KEY`).
pub(crate) const NON_CA_SELF_SIGNED_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQge4qqz64WFk3lnmiZ
I3cho+VUxn+vtRjYUqXiNY+aLlahRANCAAR+9IcfmRlsn0zHttqF7x6zlzMjHT57
uYotlGzejTA7BjnbQmE8PLr1++Kkh98Sf8LknnPL1duwGDL+PW5TsDc1
-----END PRIVATE KEY-----
";

/// Install `ring` as the process-wide rustls provider, if none is installed
/// yet. Test servers (`ServerConfig::builder`) and `reqwest` clients built
/// without a preconfigured TLS configuration read it.
pub(crate) fn install_test_provider() {
    #[expect(
        clippy::disallowed_methods,
        reason = "test servers and reqwest test clients need a process provider"
    )]
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A TLS server config presenting `cert_pem` with its own key `key_pem`.
pub(crate) fn server_config(cert_pem: &str, key_pem: &str) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    install_test_provider();
    let chain = vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    )
}

/// A TLS server config that presents [`EC_CERT_PEM`] but signs its handshake
/// with [`IMPOSTOR_EC_KEY_PKCS8_PEM`], a key that is not the certificate's.
pub(crate) fn impostor_server_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    install_test_provider();
    let cert = CertificateDer::from_pem_slice(EC_CERT_PEM.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(IMPOSTOR_EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key).unwrap();
    let certified = Arc::new(CertifiedKey::new(vec![cert], signing_key));
    Arc::new(
        rustls::ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(certified))),
    )
}

/// A TLS endpoint that counts the application bytes clients send after a
/// completed handshake. Each connection gets one read; if it returns data,
/// the bytes are added to the counter and a bodyless `500` is sent back.
/// Returns its port and the counter. Exits after 10 s without a connection.
pub(crate) fn spawn_tls_sink(config: Arc<rustls::ServerConfig>) -> (u16, Arc<AtomicUsize>) {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    const DEADLINE: Duration = Duration::from_secs(10);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let read = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&read);
    std::thread::spawn(move || {
        let start = Instant::now();
        loop {
            match listener.accept() {
                Ok((tcp, _)) => {
                    let (config, counter) = (Arc::clone(&config), Arc::clone(&counter));
                    std::thread::spawn(move || {
                        let _ = tcp.set_nonblocking(false);
                        let _ = tcp.set_read_timeout(Some(DEADLINE));
                        let _ = tcp.set_write_timeout(Some(DEADLINE));
                        let Ok(conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut tls = rustls::StreamOwned::new(conn, tcp);
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = tls.read(&mut buf)
                            && n > 0
                        {
                            counter.fetch_add(n, Ordering::SeqCst);
                            let _ = tls.write_all(
                                b"HTTP/1.1 500 Internal Server Error\r\n\
                                  Content-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                            let _ = tls.flush();
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > DEADLINE {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });
    (port, read)
}
