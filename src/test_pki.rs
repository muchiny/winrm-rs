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
//
// One EC key in two encodings (SEC1, PKCS#8) and one RSA key in PKCS#1 cover
// the three private-key formats Certificate auth accepts.

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
