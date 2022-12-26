# cryptography-kotlin

TODO until 0.1.0:

* [ ] Algorithms (+/- covered WebCrypto)
    * [ ] AES CBC/GCM (CTR?)
        * [x] algorithms
        * [x] implementations
        * [ ] box ciphers
        * [ ] function ciphers
    * [ ] EC (ECDSA/ECDH)
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA OAEP
        * [x] algorithms
        * [ ] implementations
    * [ ] RSA PSS
        * [x] algorithms
        * [ ] implementations
    * [ ] PBKDF2
    * [ ] HKDF
    * [x] Digest
        * [x] MD5, SHA-1, SHA-2
        * [ ] SHA-3
        * [ ] Hash functions
    * [x] Decide on algorithms package structure - per kind of algorithm (digest, asymmetric, symmetric, etc)
    * [x] Default Random
* [ ] Operations
    * [ ] Key encode/decode
    * [ ] Key derive/exchange/agreement
    * [ ] Key wrap/unwrap
    * [ ] Decide on cipher encrypt/decrypt functions for RSA-like algorithms
* [ ] Add tests
    * [ ] Encryption/decryption
    * [ ] Signing/verification
    * [ ] Key encode/decode
* [ ] Engines
    * [ ] OpenSSL(1/3) engine (dynamic)
    * [ ] Default engine
    * [ ] Replace thread local in JDK with super simple pooling
* [ ] Coroutines integration (for JDK engine to run on other dispatcher)
* [X] OptIn for not secure algorithms (like MD5)
* [X] OptIn for declarations, that should be used from engines only!!!
* [ ] Decide on NoArg factories - may be make them lazy instances?
* [ ] Maven Central
* [ ] README

0.2.0 plans:

* [ ] CryptoKit engine
* [ ] Security framework engine
* [ ] Windows CNG engine
* [ ] OpenSSL(1/3) engine (static)
* [ ] Engine builder DSL + decide on how to better handle providers inside engine (lazy, cache, etc)
* [ ] X.509 Certificates
* [ ] JDK Untyped support (using javax.crypto algorithms spec) - is it needed?
* [ ] JDK KeyStore
* [ ] PKCS12 support
* [ ] Android integration tests

future plans:

* [ ] AWS/GCP KMS provider
* [ ] BorringSSL engine
* [ ] NodeJS engine
* [ ] JWT/JWK support (JOSE)
* [ ] MPP ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
