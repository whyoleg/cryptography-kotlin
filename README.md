# cryptography-kotlin

TODO until 0.1.0:

* [ ] Algorithms
    * [ ] AES Box ciphers
    * [ ] EC (ECDSA/ECDH)
    * [ ] RSA OAEP
    * [ ] MD5
    * [x] Decide on algorithms package structure - per kind of algorithm (digest, asymmetric, symmetric, etc)
    * [ ] Default Randomizer algorithm
* [ ] Operations
    * [ ] Key encode/decode
    * [ ] Key derive/exchange
    * [ ] Key wrap/unwrap
* [ ] Add tests (for JVM: JDK and Android tests)
* [ ] Engines
    * [ ] OpenSSL(1/3) engine (dynamic)
    * [ ] Default engine
    * [ ] Replace thread local in JDK with super simple pooling
    * [ ] Engine builder
* [ ] Coroutines integration (for JDK engine to run on other dispatcher)
* [ ] OptIn for not secure algorithms (like MD5)
* [ ] OptIn for declarations, that should be used from engines only!!!
* [ ] Maven Central
* [ ] README

0.2.0 plans:

* [ ] CryptoKit engine
* [ ] Windows CNG engine
* [ ] Security framework engine
* [ ] OpenSSL(1/3) engine (static)
* [ ] X.509 Certificates
* [ ] JDK Untyped support (using javax.crypto algorithms spec) - is it needed?
* [ ] JDK KeyStore
* [ ] PKCS12 support

future plans:

* [ ] AWS/GCP KMS provider
* [ ] BorringSSL engine
* [ ] NodeJS engine
* [ ] JWT/JWK support (JOSE)
* [ ] MPP ASN.1/X.509/DER/PEM encoder/decoder (via kx.serialization ?)
