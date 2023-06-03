# how

Implement FingerprintClientHello to generate ClientHelloSpec from ClientHello
raw bytes:

https://github.com/refraction-networking/utls/commit/2179f286

before the first commit, lets remove large items:

~~~
handshake_client_test.go
handshake_server_test.go
testdata
~~~

now create `go.mod`:

~~~
go mod init 2a.pages.dev/tls
~~~

create `go.sum`:

~~~
go mod tidy
~~~

remove:

~~~
.travis.yml
CONTRIBUTING.md
CONTRIBUTORS_GUIDE.md
README.md
auth_test.go
conn_test.go
cpu
example_test.go
examples
generate_cert.go
handshake_messages_test.go
handshake_test.go
key_schedule_test.go
logo.png
logo_small.png
prf_test.go
testenv
tls_test.go
u_common_test.go
u_conn_test.go
u_fingerprinter_test.go
~~~

then:

~~~diff
+++ b/common.go
@@ -21,2 +20,0 @@ import (
-
-       "github.com/refraction-networking/utls/cpu"
~~~

error:

~~~
common.go:923:20: undefined: cpu
~~~

fix:

~~~diff
+++ b/common.go
@@ -1097,46 +1097,14 @@ func initDefaultCipherSuites() {
-       var topCipherSuites []uint16
-
-       // Check the cpu flags for each platform that has optimized GCM implementations.
-       // Worst case, these variables will just all be false.
-       var (
-               hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
-               hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
-               // Keep in sync with crypto/aes/cipher_s390x.go.
-               // hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)
-               hasGCMAsmS390X = false // [UTLS: couldn't be bothered to make it work, we won't use it]
-
-               hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
-       )
-
-       if hasGCMAsm {
-               // If AES-GCM hardware is provided then prioritise AES-GCM
-               // cipher suites.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-               }
-               varDefaultCipherSuitesTLS13 = []uint16{
-                       TLS_AES_128_GCM_SHA256,
-                       TLS_CHACHA20_POLY1305_SHA256,
-                       TLS_AES_256_GCM_SHA384,
-               }
-       } else {
-               // Without AES-GCM hardware, we put the ChaCha20-Poly1305
-               // cipher suites first.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-               }
-               varDefaultCipherSuitesTLS13 = []uint16{
-                       TLS_CHACHA20_POLY1305_SHA256,
-                       TLS_AES_128_GCM_SHA256,
-                       TLS_AES_256_GCM_SHA384,
-               }
+       // Without AES-GCM hardware, we put the ChaCha20-Poly1305
+       // cipher suites first.
+       topCipherSuites := []uint16{
+               TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
+               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
+       }
+       varDefaultCipherSuitesTLS13 = []uint16{
+               TLS_CHACHA20_POLY1305_SHA256,
+               TLS_AES_128_GCM_SHA256,
+               TLS_AES_256_GCM_SHA384,
~~~

fix:

~~~diff
+++ b/cipher_suites.go
@@ -17,2 +16,0 @@ import (
-
-       "golang.org/x/crypto/chacha20poly1305"
~~~

error:

~~~
cipher_suites.go:232:15: undefined: chacha20poly1305
~~~

fix:

~~~diff
@@ -231,11 +230,0 @@ func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
-func aeadChaCha20Poly1305(key, fixedNonce []byte) cipher.AEAD {
-       aead, err := chacha20poly1305.New(key)
-       if err != nil {
-               panic(err)
-       }
-
-       ret := &xorNonceAEAD{aead: aead}
-       copy(ret.nonceMask[:], fixedNonce)
-       return ret
-}
-
~~~

errors:

~~~
cipher_suites.go:79:99: undefined: aeadChaCha20Poly1305
cipher_suites.go:80:116: undefined: aeadChaCha20Poly1305
~~~

fix:

~~~diff
-{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
-{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
~~~

error:

~~~
u_common.go:131:57: undefined: aeadChaCha20Poly1305
u_common.go:133:70: undefined: aeadChaCha20Poly1305
~~~

fix:

~~~diff
@@ -124,2 +123,0 @@ func utlsMacSHA384(version uint16, key []byte) macFunction {
-var utlsSupportedCipherSuites []*cipherSuite
-
@@ -129,7 +126,0 @@ func init() {
-       utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
-               {OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
-                       suiteECDHE | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
-               {OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
-                       suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
-       }...)
-
~~~

error:

~~~
u_common.go:136:2: undefined: utlsSupportedCipherSuites
~~~

fix:

~~~diff
@@ -130,16 +129,0 @@ func init() {
-
-// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
-// This provides better compatibility with servers on the web, but weakens security. Feel free
-// to use this option if you establish additional secure connection inside of utls connection.
-// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
-func EnableWeakCiphers() {
-       utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
-               {DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
-                       suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
-
-               {DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
-                       suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
-               {DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
-                       suiteECDHE | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
-       }...)
-}
~~~

error:

~~~
cipher_suites.go:338:26: undefined: utlsSupportedCipherSuites
~~~

fix:

~~~diff
-for _, suite := range utlsSupportedCipherSuites { // [UTLS]
+for _, suite := range cipherSuites {
~~~

warning:

~~~
conn.go:618:40: e.Temporary has been deprecated since Go 1.18 because it
shouldn't be used: Temporary errors are not well-defined. Most "temporary"
errors are timeouts, and the few exceptions are surprising. Do not use this
method.  (SA1019)

conn.go:657:40: e.Temporary has been deprecated since Go 1.18 because it
shouldn't be used: Temporary errors are not well-defined. Most "temporary"
errors are timeouts, and the few exceptions are surprising. Do not use this
method.  (SA1019)
~~~

fix:

~~~diff
@@ -617,0 +618,2 @@ func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
+               //lint:ignore SA1019 reason
+               // github.com/golang/go/blob/go1.20.4/src/crypto/tls/conn.go#L663
@@ -656,0 +659,2 @@ func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
+               //lint:ignore SA1019 reason
+               // github.com/golang/go/blob/go1.20.4/src/crypto/tls/conn.go#L663
~~~

warning:

~~~
key_schedule.go:198:2: curve25519.ScalarMult is deprecated: when provided a
low-order point, ScalarMult will set dst to all zeroes, irrespective of the
scalar. Instead, use the X25519 function, which will return an error.  (SA1019)
~~~

fix:

https://github.com/golang/go/commit/d88d91e3
