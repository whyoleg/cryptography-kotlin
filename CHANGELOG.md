# CHANGELOG

## 0.3.0 - Support for ALL targets, new experimental modules

> Published 21 Feb 2024

### New Kotlin targets

* `cryptography-core` and `cryptography-random` modules are now supported for **ALL** Kotlin targets!
* CryptographyRandom implementation for WasmJs and WasmWasi
* WebCrypto provider for WasmJs
* OpenSSL provider now supports **ALL** K/N targets ([#10](https://github.com/whyoleg/cryptography-kotlin/issues/10))
    * new targets: linuxArm64, tvOS*, watchOS*, androidNative*

### New features

* RSA (PSS, OAEP, PKCS1) support in Apple provider ([#12](https://github.com/whyoleg/cryptography-kotlin/issues/12))
* RSA PKCS#1 key encoding support
* New algorithm support: AES-CTR
* Support for explicitly provided IV in AES-CTR and AES-CBC
    * **Note:** these APIs are marked as `DelicateCryptographyApi`,
      and so should be used only when it's really required as they are easy to misuse

### Bug fixes

* Fix mingw linking because of zlib ([#13](https://github.com/whyoleg/cryptography-kotlin/issues/13))

### Breaking changes

* Replace InsecureAlgorithm annotation with DelicateCryptographyApi - API breaking change
* `publicExponent` parameter in RSA `keyPairGenerator` is now of type `BigInt` - both API and ABI breaking change
* RSA key formats are now implemented via `sealed class` instead of `enum` - ABI breaking change
*

### General improvements

* Kotlin 1.9.22
* Update the prebuilt OpenSSL version to 3.2.0
* Test OpenSSL provider over 3.0, 3.1, 3.2
* A lot of changes and improvements to build, tests and CI configuration

### Experimental features

* Introduce support for BigInt
    * use platform specifics where possible
    * RSA public exponent now works in the same way for all providers
    * all Kotlin targets supported
* Introduce support for PEM encoding/decoding
    * fully common implementation
* Introduce support for ASN.1/DER serialization
    * fully common implementation via [kotlinx.serialization](https://github.com/Kotlin/kotlinx.serialization)

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
