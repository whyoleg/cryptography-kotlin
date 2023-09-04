# Future versions planning

## 0.3.0: New operations, algorithms, engines

* Operations
    * Key agreement
    * Key derive (kdf/prf)
    * Multi-key agreement support
    * Key wrap/unwrap
    * OTP (One Time Password) support
* Algorithms
    * AES-KW (key wrap/unwrap)
    * ChaCha20-Poly1305 (stream cipher)
    * ECDH (key agreement)
    * PBKDF2 (prf)
    * HKDF (kdf)
    * Agron2 (prf)
    * scrypt (prf)
    * brcypt (prf)
    * CMAC (mac) - how to configure it? check BC and OpenSSL
    * Blowfish (cipher), Blake (hash) - try to find some implementations (?)
    * TOTP/HOTP (otp)
    * AES-CTR (cipher)
        * TBD: how API for it should look like regarding IV/Nonce/Counter - looks like better to be implicitly provided
    * SHAKE (hash)
    * Ed25519 curve
  * decide on Digest/SHA/Hash algorithms naming and usage
* Engines
    * CryptoKit engine
    * Windows CNG engine
    * watchos/tvos: OpenSSL3/Apple
    * OpenSSL3 update static to 3.1
        * Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
    * add testing on JDK + conscrypt
* Tests
    * Add assertion in compatibility tests on number of tested combinations
    * write MORE tests for failures - decide on how to better test everything, specifically failures and exeptional situations
    * Integrate with https://github.com/google/wycheproof to test against test vectors
      (more tests here https://github.com/pyca/cryptography/blob/main/docs/development/test-vectors.rst)
    * add some tracking on which combinations of tests are executed...
    * better caching in tests (ciphers/signature* like keys)
    * rework testtool to use WebSockets
    * setup testing of OpenSSL provider over multiple minor versions
        * update static to version 3.1.x (while leaving dynamic to 3.0.x)
        * setup testing over 3.0.x and 3.1.x dynamically
    * decide on how additional android tests should be run (cryptography-random tests only for now)
  * Need to decide on how to better check what is tested and what is not; what is supported and what is not
* Infrastructure:
    * setup Dependabot/Renovate
    * setup kover merged report
    * publish kover report somewhere (https://github.com/mi-kas/kover-report)
    * publish test report on CI
    * Qodana/CodeQL integration
    * setup mkdocs for current + preview versions
    * setup changelog managing
    * setup CI builds for pull requests
* Documentation:
    * add info about testing
    * add FAQ about security related things
    * add documentation to declarations
    * setup dokka to fail on undocumented

## 0.4.0: Certificates and Key management

* Materials
    * introduce materials: key, key pair, certificate, certificate chain, certificate+key pair etc
    * X.509 Certificates
    * PKCS12 support
    * Keys/Certificates management
        * keystore/keymanager/keychain/keyring?
        * Destination: java key store, keychain, file (?), secure enclave (?)
        * JDK KeyStore (?)
* General
    * General way to define algorithms, that support something (like KeyGen, needed for certificates)
    * Decide on how someone can create custom algorithms, that need or ECDSA.Key or RSA.PSS.Key
      (like different signature algorithms in ssh, tls, certificate)
    * Decode key from DER/PEM -> then decide on which algorithm it is (problems with WebCrypto)

## 0.5.0: Enhanced operations for big data and streaming (some things can depend on IO library - if so, design or postpone)

* Function operations (cipher, signature, hash)
* Operations with provided output buffer
* functions for calculating signature/digest/plaintext/etc sizes
* encrypt/decrypt
    * Box ciphers
    * Unsafe/Parameterized encrypt operations for cases when f.e. AES nonce/iv provided by user
    * Decide on cipher encrypt/decrypt functions for RSA-like algorithms
    * Streaming encryption/decryption (look at google/tink)
    * File encryption/decryption (function operations)
    * JDK in-place encryption/decryption (use single ByteArray for output (generate IV in place, and output it))

## Kotlin x.y.z:

* WebCrypto WASM(JS) support (1.9.0: still has no simple libraries releases)
* use kotlin.Closeable (1.9.0: still experimental)
* use base64 from stdlib (1.9.0: still experimental)
* setup configuration cache (1.9.0: has issues)

## x.y.z plans:

* compiler plugin to generate declarations with flatten parameters (related to 'general way to define algorithms')
* Extensions - something, that can be linked automatically, but also can be configured explicitly
    * Coroutines integration (for JDK engine to run on other dispatcher, to avoid blocking main thread) - is it needed?
    * PEM support as extension
    * JWK support as extension
* Engines
    * AWS/GCP KMS provider
    * BorringSSL engine (MPP)
    * NodeJS engine
    * OpenSSL3 engine for JVM (may be JS/WASM)
    * OpenSSL 1.1.1 - is it needed?
    * Apple: EC/RSA via Security framework (no DER key encoding out of the box)
    * WASM WASI - is there something available?
    * align exceptions between engines
* MPP encoding
    * JWT/JWK support (JOSE)
    * ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
* Operations/Algorithms
    * Hybrid Encryption
    * Double Ratchet Algorithm (?)
* Try to implement some TLS cipher suites (TLS 1.2/1.3) in sample or as a separate module
* Extract popular digests into separate module with only non-suspend impl? (?)
* Supports testing DER keys not by content equality, but by parsing and comparing
* JDK pooling for SPIs (f.e. looks like Signature is poolable only by parameters, and not by algorithm)
* integrations
    * https://github.com/Password4j/password4j
    * https://github.com/keycloak/keycloak
* use knit when it will work with current kotlin version
* Investigate WASI-crypto support
* FIPS (?)
* JPMS support (when kx.* libraries will support it)
* RSA-PSS salt size values: digest size, max size, plain value
* Somehow check, that there is no memory leaks (especially in openssl provider)
* Add pooling in openssl provider
* linuxArm64 and androidNative* support - need some way to test it

## 1.0.0: Stable release

* Design CryptographyException hierarchy
* Migrate to kotlinx-io
* Use some BigInt library/implementation (f.e. for RSA.PublicExponent)
* Decide on algorithms access in code. f.e. AES.CBC, RSA.OAEP vs ECDSA, ECDH, etc.
    * algorithms - AesBasedAlgorihm, RsaBasedAlgorithm, AesGcmAlgorithm
    * ids -> AES.CBC, RSA.OAEP, RSA, etc.
* Decide on operations default carefully
* Decide on suspend and non-suspend functions
