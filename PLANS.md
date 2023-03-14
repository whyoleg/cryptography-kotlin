# Future versions planning

## 0.1.0: Initial release

* [ ] Tests
    * [ ] investigate compatibility test failure on JS browser - Key R(* -> *) is missing in the map completing
    * [ ] investigate JVM compatibility tests on CI
    * [ ] write MORE behaviour tests
        * [ ] add test for decrypto ciphertext equal to iv size
        * [ ] write behaviour tests for failures
    * [ ] Setup cross-platform compatibility tests on CI
* [ ] Build
    * [ ] Samples (for each different kind of operation) - decide on how to include them
    * [ ] setup kover merged report
    * [ ] setup toolchains compatible with gradle 8
* [ ] CI
    * [ ] publish dokka HTML
    * [ ] setup Dependabot
    * [ ] publish kover report somewhere
    * [ ] setup workflow for release publishing
    * [ ] Maven Central (check)
    * [ ] Qodana/CodeQL integration
* [ ] Doc
    * [ ] actualize README with some high-level information about library and some links
    * [ ] add info about testing to README
    * [ ] add FAQ about security related things to README
    * [ ] add kotlin documentation to ALL declarations (there are not so much of them TBH)

## 0.2.0: New operations, algorithms, engines

* [ ] Operations
    * [ ] Key agreement
    * [ ] Key derive (kdf/prf)
    * [ ] Multi-key agreement support
    * [ ] Key wrap/unwrap
    * [ ] OTP (One Time Password) support
* [ ] Algorithms
    * [ ] SHA-3 (hash)
    * [ ] SHAKE (hash)
    * [ ] AES-KW (key wrap/unwrap)
    * [ ] AES-CTR (cipher)
    * [ ] ChaCha20-Poly1305 (stream cipher)
    * [ ] ECDH (key agreement)
    * [ ] PBKDF2 (prf)
    * [ ] HKDF (kdf)
    * [ ] Agron2 (prf)
    * [ ] scrypt (prf)
    * [ ] brcypt (prf)
    * [ ] RSA-SSA-PKCS1 (signature)
    * [ ] Ed25519 curve
    * [ ] CMAC (mac)
    * [ ] Blowfish (cipher), Blake (hash) - try to find some implementations (?)
    * [ ] TOTP/HOTP (otp)
* [ ] Engines
    * [ ] CryptoKit engine
    * [ ] Windows CNG engine
    * [ ] watchos/tvos: OpenSSL3/Apple
    * [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
* [ ] Tests
    * [ ] Android integration tests
    * [ ] JDK with Bouncy Castle tests
    * [ ] Integrate with https://github.com/google/wycheproof to test against test vectors
      (more tests here https://github.com/pyca/cryptography/blob/main/docs/development/test-vectors.rst)
    * [ ] Add assertion in compatibility tests on amount of tested combinations
    * [ ] better caching in tests (ciphers/signature* like keys)
    * [ ] Refactor currentPlatform in tests with some kind of object per platform with properties

## Kotlin 1.8.20/1.9.0

* [ ] WebCrypto WASM support
* [ ] use kotlin.Closeable
* [ ] migrate test-client to composite build
* [ ] use base64 from stdlib
* [ ] setup configuration cache

## 0.3.0: Certificates and Key management

* [ ] Materials
    * [ ] introduce materials: key, key pair, certificate, certificate chain, certificate+key pair etc
    * [ ] X.509 Certificates
    * [ ] PKCS12 support
    * [ ] Keys/Certificates management
        * [ ] keystore/keymanager/keychain/keyring?
        * [ ] Destination: java key store, keychain, file (?), secure enclave (?)
        * [ ] JDK KeyStore (?)
* [ ] General
    * [ ] General way to define algorithms, that support something (like KeyGen, needed for certificates)
    * [ ] Decide on how someone can create custom algorithms, that need or ECDSA.Key or RSA.PSS.Key
      (like different signature algorithms in ssh, tls, certificate)
    * [ ] Decode key from DER/PEM -> then decide on which algorithm it is (problems with WebCrypto)

## 0.4.0: Enhanced operations for big data and streaming (some things can depend on IO library - if so, design or postpone)

* [ ] Function operations (cipher, signature, hash)
* [ ] Operations with provided output buffer
* [ ] functions for calculating signature/digest/plaintext/etc sizes
* [ ] encrypt/decrypt
    * [ ] Box ciphers
    * [ ] Unsafe/Parameterized encrypt operations for cases when f.e. AES nonce/iv provided by user
    * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
    * [ ] Streaming encryption/decryption (look at google/tink)
    * [ ] File encryption/decryption (function operations)
    * [ ] JDK in-place encryption/decryption (use single ByteArray for output (generate IV in place, and output it))

## x.y.z plans:

* [ ] compiler plugin to generate declarations with flatten parameters (related to 'general way to define algorithms')
* [ ] Extensions - something, that can be linked automatically, but also can be configured explicitly
    * [ ] Coroutines integration (for JDK engine to run on other dispatcher, to avoid blocking main thread) - is it needed?
    * [ ] PEM support as extension
    * [ ] JWK support as extension
* [ ] Engines
    * [ ] AWS/GCP KMS provider
    * [ ] BorringSSL engine (MPP)
    * [ ] NodeJS engine
    * [ ] OpenSSL3 engine for JVM (may be JS/WASM)
    * [ ] OpenSSL 1.1.1 - is it needed?
    * [ ] Apple: EC/RSA via Security framework (no DER key encoding out of the box)
* [ ] MPP encoding
    * [ ] JWT/JWK support (JOSE)
    * [ ] ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
* [ ] Operations/Algorithms
    * [ ] Hybrid Encryption
    * [ ] Double Ratchet Algorithm (?)
* [ ] Try to implement some TLS cipher suites (TLS 1.2/1.3) in sample or as a separate module
* [ ] Extract popular digests into separate module with only non-suspend impl? (?)
* [ ] Supports testing DER keys not by content equality, but by parsing and comparing
* [ ] JDK pooling for SPIs (f.e. looks like Signature is poolable only by parameters, and not by algorithm)
* [ ] integrations
    * [ ] https://github.com/Password4j/password4j
    * [ ] https://github.com/keycloak/keycloak
* [ ] use knit when it will work with current kotlin version
* [ ] Investigate WASI-crypto support
* [ ] FIPS (?)
* [ ] JPMS support (when kx.* libraries will support it)
* [ ] RSA-PSS salt size values: digest size, max size, plain value
* [ ] Somehow check, that there is no memory leaks (especially in openssl provider)
* [ ] Add pooling in openssl provider

## 1.0.0: Stable release

* [ ] Design CryptographyException hierarchy
* [ ] Migrate to some IO library
* [ ] Use some BigInt library/implementation (f.e. for RSA.PublicExponent)
* [ ] Decide on algorithms access in code. f.e. AES.CBC, RSA.OAEP vs ECDSA, ECDH, etc.
    * [ ] algorithms - AesBasedAlgorihm, RsaBasedAlgorithm, AesGcmAlgorithm
    * [ ] ids -> AES.CBC, RSA.OAEP, RSA, etc.
* [ ] Decide on operations default carefully
* [ ] Decide on suspend and non-suspend functions
