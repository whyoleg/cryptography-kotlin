# cryptography-kotlin

0.1.0 plans:

* [ ] Algorithms (+/- covered WebCrypto)
    * [ ] EC (ECDSA/ECDH)
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA OAEP
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA PSS
        * [x] algorithms
        * [ ] implementations
    * [x] Decide on algorithms package structure - per kind of algorithm (digest, asymmetric, symmetric, etc)
    * [x] Default Random
* [ ] Operations
    * [ ] Key encode/decode (or import/export?)
* [ ] Tests
    * [ ] Encryption/decryption
    * [ ] Signing/verification
    * [ ] Key encode/decode
* [ ] Engines
    * [ ] WebCrypto
    * [ ] JDK
    * [ ] CoreCrypto
    * [ ] OpenSSL(1/3) engine (dynamic)
    * [ ] Default engine
    * [ ] Replace thread local in JDK with super simple pooling
* [ ] Coroutines integration (for JDK engine to run on other dispatcher)
* [X] OptIn for not secure algorithms (like MD5)
* [X] OptIn for declarations, that should be used from engines only!!!
* [ ] Maven Central
* [ ] README

0.2.0 plans:

* [ ] Algorithms
    * [ ] SHA-3
    * [ ] AES-CTR (?)
    * [ ] PBKDF2
    * [ ] HKDF
    * [ ] RSA-SSA-PKCS1
    * [ ] CMAC
* [ ] Operations
    * [ ] Function operations (cipher, signature, hash)
    * [ ] Key derive (kdf/prf)
        * [ ] Multi-key derive support
    * [ ] encrypt/decrypt
        * [ ] Box ciphers
        * [ ] Unsafe encrypt operations for cases when f.e. AES nonce/iv provided by user
        * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
        * [ ] Streaming encryption/decryption (look at google/tink)
        * [ ] File encryption/decryption (function operations)
    * [ ] Key wrap/unwrap
* [ ] Engines
    * [ ] CryptoKit engine
    * [ ] Security framework engine
    * [ ] Windows CNG engine
    * [ ] OpenSSL(1/3) engine (static)
    * [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
* [ ] Decide on NoArg factories - may be make them lazy instances?
* [ ] X.509 Certificates
* [ ] JDK KeyStore
* [ ] PKCS12 support
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
