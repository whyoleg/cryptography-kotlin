# CHANGELOG

## 0.3.0

> Published XX Feb 2024

## 0.2.0 - New algorithms, Android integration testing

> Published 5 Sep 2023

### New algorithms

* RSA.PKCS1 (RSAES-PKCS1-v1_5) - supported by JDK, WebCrypto and OpenSSL3 providers #5
* SHA224 - supported by JDK, OpenSSL3 and Apple providers
* SHA3 family - supported by JDK and OpenSSL3 providers

### Testing improvements

* Support running tests with [BouncyCastle](https://www.bouncycastle.org) in addition to default JDK provider
* Support running JDK provider tests on Android emulator with API level 21, 27 and 30
* Add ECDSA with `secp256k1` curve testing (supported by JDK BouncyCastle and OpenSSL3 providers) #4

### General improvements

* Kotlin 1.9.10
* a lot of under the hood changes to improve test coverage and test correctness

### Breaking changes

* providers artifacts and package name changes. F.e. for JDK provider:
    * maven artifact name changed from `cryptography-jdk` to `cryptography-provider-jdk`
    * package name changed from `dev.whyoleg.cryptography.jdk` to `dev.whyoleg.cryptography.providers.jdk`
* several classes and annotation changed package name to `dev.whyoleg.cryptography` to simplify hierarchy:
    * `CryptographyAlgorithm`
    * `CryptographyAlgorithmNotFoundException`
    * `CryptographyProvider`
    * `CryptographyProviderApi`
    * `InsecureAlgorithm`
* simplified JDK provider with custom provider creation
    * `JdkProvider` class removed
    * [`java.security.Provider`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Provider.html) or it's name can
      be now directly provided in constructor function
        * before: `CryptographyProvider.JDK(JdkProvider.Instance(BouncyCastleProvider()))`
          or `CryptographyProvider.JDK(JdkProvider.Name("BC"))`
        * now: `CryptographyProvider.JDK(BouncyCastleProvider())` or `CryptographyProvider.JDK("BC")`

## 0.1.0 - First release

> Published 23 Mar 2023
