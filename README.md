# cryptography-kotlin

0.1.0 plans:

* [ ] Algorithms (+/- covered WebCrypto)
    * [ ] AES CBC/GCM (CTR?)
        * [x] algorithms
        * [x] implementations
        * [ ] box ciphers
    * [ ] EC (ECDSA/ECDH)
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA OAEP
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA PSS
        * [x] algorithms
        * [ ] implementations
    * [x] Digest
        * [x] MD5, SHA-1, SHA-2
        * [ ] SHA-3
    * [x] Decide on algorithms package structure - per kind of algorithm (digest, asymmetric, symmetric, etc)
    * [x] Default Random
* [ ] Operations
    * [x] Drop functions operations for now
    * [ ] Key encode/decode (or import/export?)
    * [ ] Unsafe encrypt operations for cases when f.e. AES nonce/iv provided by user
* [ ] Add tests
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

* [ ] Operations
    * [ ] Key derive
        * [ ] PBKDF2
        * [ ] HKDF
    * [ ] Design multi-key derive support
    * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
    * [ ] Function operations (cipher, signature, hash)
    * [ ] Streaming encryption/decryption (look at google/tink)
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

POSSIBLE future plans:

* [ ] AWS/GCP KMS provider
* [ ] BorringSSL engine
* [ ] NodeJS engine
* [ ] JWT/JWK support (JOSE)
* [ ] MPP ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
* [ ] JDK Untyped support (using javax.crypto algorithms spec) - is it needed?
