# Future versions planning

## 0.1.0: Initial release

* [ ] Other
    * [ ] drop blocking/suspend adaptors
* [ ] Tests
    * [ ] Key agreement
    * [ ] Optimize tests (cache keys?)
* [ ] Engines
    * [ ] JDK (ECDH left)
    * [ ] Apple (CoreCrypto (done) + Security framework (not started))
    * [ ] OpenSSL(1/3) engine (dynamic/static for desktop native targets)
* [ ] Build
    * [ ] Binary compatibility validator
    * [ ] GitHub Actions vis github-workflows-kt
    * [ ] Samples (use knit?) (for each different kind of operation)
    * [ ] Dokka (at least to generate public API)
    * [ ] Kover (for coverage)
    * [ ] Maven Central
* [ ] README
    * [ ] modules/dependencies
    * [ ] supported algorithms/operations (+ not supported by some providers)
    * [ ] some intro on what this library is and testing

## 0.2.0: New operations, algorithms, engines

* [ ] Operations
    * [ ] Key derive (kdf/prf)
    * [ ] Multi-key agreement support
    * [ ] Key wrap/unwrap
* [ ] Algorithms
    * [ ] SHA-3 (hash)
    * [ ] SHAKE (hash)
    * [ ] AES-KW (key wrap/unwrap)
    * [ ] AES-CTR (?) (cipher)
    * [ ] ChaCha20-Poly1305 (stream cipher)
    * [ ] PBKDF2 (prf)
    * [ ] HKDF (kdf)
    * [ ] Agron2 (prf)
    * [ ] scrypt (prf)
    * [ ] brcypt (prf)
    * [ ] RSA-SSA-PKCS1 (signature)
    * [ ] CMAC (mac)
    * [ ] Blowfish (cipher), Blake (hash) - try to find some implementations (?)
* [ ] Engines
    * [ ] WebCrypto WASM support (need kotlin 1.8.20 stable (or at least beta))
    * [ ] CryptoKit engine
    * [ ] Windows CNG engine
    * [ ] OpenSSL(1/3) engine (static for almost all native targets)
    * [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
* [ ] Android integration tests
* [ ] JDK with BC tests

## 0.3.0: Certificates and Key management

* [ ] Materials
    * [ ] introduce materials: key, key pair, certificate, certificate chain, certificate+key pair etc
    * [ ] X.509 Certificates
    * [ ] PKCS12 support
    * [ ] Keys
        * [ ] keystore/keymanager/keychain/keyring?
        * [ ] Destination: java key store, keychain, file (?), secure enclave (?)
        * [ ] JDK KeyStore (?)
* [ ] General
    * [ ] General way to define algorithms, that support something (like KeyGen, needed for certificates)
    * [ ] Decide on how someone can create custom algorithms, that need or ECDSA.Key or RSA.PSS.Key
      (like different signature algorithms in ssh, tls, certificate)
    * [ ] Decode key from DER -> then decide on which algorithm it is (problems with WebCrypto)

## 0.4.0: Enhanced operations for bigger data and streaming (some things can depend on IO library - if so, design or postpone)

* [ ] Function operations (cipher, signature, hash)
* [ ] Operations with provided output buffer
* [ ] funcitons for calculating signature/digest/plaintext/etc sizes
* [ ] encrypt/decrypt
    * [ ] Box ciphers
    * [ ] Unsafe encrypt operations for cases when f.e. AES nonce/iv provided by user
    * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
    * [ ] Streaming encryption/decryption (look at google/tink)
    * [ ] File encryption/decryption (function operations)

## x.y.z plans:

* [ ] compiler plugin to generate declarations with flatten parameters (related to 'general way to define algorithms')
* [ ] Coroutines integration (for JDK engine to run on other dispatcher, to avoid blocking main thread) - is it needed?
* [ ] Engines
    * [ ] AWS/GCP KMS provider
    * [ ] BorringSSL engine (MPP)
    * [ ] NodeJS engine
    * [ ] OpenSSL(1/3) engine for JVM (may be JS/WASM)
* [ ] MPP encoding
    * [ ] JWT/JWK support (JOSE)
    * [ ] ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
* [ ] Operations/Algorithms
    * [ ] Hybrid Encryption
    * [ ] Double Ratchet Algorithm (?)
* [ ] Try to implement some TLS cipher suites (TLS 1.2/1.3) in sample or as a separate module
* [ ] Integrate with https://github.com/google/wycheproof to test against test vectors (more tests
  here https://github.com/pyca/cryptography/blob/main/docs/development/test-vectors.rst)

## 1.0.0: Stable release

* [ ] Design CryptographyException hierarchy
* [ ] Migrate to some IO library
* [ ] Decide on algorithms access in code. f.e. AES.CBC, RSA.OAEP vs ECDSA, ECDH, etc.
