# cryptography-kotlin

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
    * [ ] CoreCrypto
    * [ ] OpenSSL(1/3) engine (dynamic)
    * [ ] Default engine
    * [ ] Replace thread local in JDK with super simple pooling
* [ ] Coroutines integration (for JDK engine to run on other dispatcher)
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
* [ ] Operations
    * [ ] Function operations (cipher, signature, hash)
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
    * [ ] JDK KeyStore
    * [ ] PKCS12 support
* [ ] Engines
    * [ ] CryptoKit engine
    * [ ] Security framework engine
    * [ ] Windows CNG engine
    * [ ] OpenSSL(1/3) engine (static)
    * [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
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
* [ ] no-dependencies cryptogrpahy-random module with platform-specific implementations (?)
* [ ] Decide on algorithms access in code. f.e. AES.CBC, RSA.OAEP vs ECDSA, ECDH, etc.
