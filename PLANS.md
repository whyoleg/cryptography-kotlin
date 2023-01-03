0.1.0 TODO:

* [ ] Algorithms (+/- covered WebCrypto)
    * [ ] EC (ECDSA/ECDH)
        * [ ] implementations
    * [ ] RSA OAEP
        * [ ] implementations
    * [ ] RSA PSS
        * [ ] implementations
* [ ] Tests
    * [ ] Hash
    * [ ] Encryption/decryption
    * [ ] Signing/verification
    * [ ] Key import/export
    * [ ] Key agreement
* [ ] Engines
    * [ ] JDK
    * [ ] Apple (CoreCrypto + Security framework)
    * [ ] OpenSSL(1/3) engine (dynamic)
* [ ] Coroutines integration (for JDK engine to run on other dispatcher)
* [ ] no-dependencies cryptogrpahy-random module with platform-specific implementations (?)
* [ ] Maven Central
* [ ] README

0.2.0-0.3.0 plans:

* [ ] Algorithms
    * [ ] SHA-3 (hash)
    * [ ] AES-CTR (?) (cipher)
    * [ ] ChaCha20-Poly1305 (stream cipher)
    * [ ] PBKDF2 (prf)
    * [ ] HKDF (kdf)
    * [ ] Agron2 (prf)
    * [ ] scrypt (prf)
    * [ ] brcypt (prf)
    * [ ] RSA-SSA-PKCS1 (signature)
    * [ ] CMAC (mac)
    * [ ] Blowfish (cipher), Blake (hash)- try to find some implementations
* [ ] Operations (some things can depend on IO library - if so, design or postpone)
    * [ ] Function operations (cipher, signature, hash)
    * [ ] Operations with provided output buffer
    * [ ] Key derive (kdf/prf)
    * [ ] Multi-key agreement support
    * [ ] encrypt/decrypt
        * [ ] Box ciphers
        * [ ] Unsafe encrypt operations for cases when f.e. AES nonce/iv provided by user
        * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
        * [ ] Streaming encryption/decryption (look at google/tink)
        * [ ] File encryption/decryption (function operations)
    * [ ] Key wrap/unwrap
* [ ] Materials
    * [ ] introduce materials: key, key pair, certificate, certificate chain, certificate+key pair etc
    * [ ] X.509 Certificates
    * [ ] PKCS12 support
    * [ ] Keys
        * [ ] keystore/keymanager/keychain/keyring?
        * [ ] Destination: java key store, key chain, file, secure enclave (?)
        * [ ] JDK KeyStore
* [ ] Engines
    * [ ] CryptoKit engine
    * [ ] Windows CNG engine
    * [ ] OpenSSL(1/3) engine (static)
    * [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
    * [ ] Default (auto provision) engine
* [ ] Android integration tests

0.x.y plans:

* [ ] CryptographyException hierarchy
* [ ] AWS/GCP KMS provider
* [ ] BorringSSL engine
* [ ] NodeJS engine
* [ ] JWT/JWK support (JOSE)
* [ ] MPP ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
* [ ] JDK Untyped support (using javax.crypto algorithms spec) - is it needed?
* [ ] Hybrid Encryption
* [ ] Double Ratchet Algorithm (?)
* [ ] Decide on algorithms access in code. f.e. AES.CBC, RSA.OAEP vs ECDSA, ECDH, etc.
* [ ] key usages (like in WebCrypto) - is it needed?
* [ ] migrate to some IO library
