# Overview

```kotlin
CryptographyProvider.Default
    .get(SHA512)
    .hasher()
    .hash("Kotlin is Awesome".encodeToByteArray())
```

cryptography-kotlin provides multiplatform API which consists of multiple components:

* [Secure random][Secure random] with [kotlin.Random][kotlin.Random] like API which can be used independently of other modules
* common API to use different cryptography operations,
  like [ciphers][ciphers], [digests][digests], [signatures][signatures], [key derivation][key derivation], [Key agreement][Key agreement]
* multiple algorithms definitions, like [AES][AES], [RSA][RSA], [ECDSA][ECDSA], [ECDH][ECDH], [SHA][SHA256], [HMAC][HMAC]
  and [PBKDF2][PBKDF2]
* multiple cryptography [providers][providers], like [OpenSSL][OpenSSL], [WebCrypto][WebCrypto], [CryptoKit][CryptoKit] and [JDK][JDK]

The library doesn't implement any cryptography algorithm on its own, but wraps well-known future-proof solutions
like [OpenSSL 3.x](https://www.openssl.org), [CryptoKit](https://developer.apple.com/documentation/cryptokit/),
[WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
or [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
with type-safe multiplatform API providing uniform experience with aligned default behavior,
and same expected results using identical parameters while allowing to use platform-specific capabilities.
For supported algorithms, primitives and targets, please consult [Providers documentation][providers]

Core primitives are:

* [CryptographyProvider][CryptographyProvider] provides a way to get specific [CryptographyAlgorithm][CryptographyAlgorithm] by its id
* [CryptographyProvider.Default][CryptographyProvider.Default] is the default provider.
  After adding a dependency to a provider (like openssl3), it will be automatically registered and available via the default provider
* inheritors of [CryptographyAlgorithm][CryptographyAlgorithm] (like f.e. [AES][AES]) provide access to operations (like
  f.e. [ciphers][ciphers])

## Using in your projects

Make sure that you use Kotlin 2.2.0+. Using an earlier Kotlin version could still work, but not tested.
The library is published to Maven Central, so make sure that it’s added to repositories.

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-core:0.5.0")
            implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.5.0")
        }
    }
}
```

Additionally, it's possible to use [BOM][BOM] or [Gradle version catalog][Gradle version catalog] to add dependencies easier.

[Secure random]: random.md

[kotlin.Random]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.random/-random/

[ciphers]: api/cryptography-core/dev.whyoleg.cryptography.operations/-cipher/index.html

[digests]: api/cryptography-core/dev.whyoleg.cryptography.operations/-hasher/index.html

[signatures]: api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/index.html

[key derivation]: api/cryptography-core/dev.whyoleg.cryptography.operations/-secret-derivation/index.html

[Key agreement]: api/cryptography-core/dev.whyoleg.cryptography.operations/-shared-secret-generator/index.html

[SHA256]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-s-h-a256/index.html

[AES]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-a-e-s/index.html

[HMAC]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-m-a-c/index.html

[RSA]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-r-s-a/index.html

[ECDSA]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-s-a/index.html

[ECDH]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-h/index.html

[PBKDF2]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-p-b-k-d-f2/index.html

[HKDF]: api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-k-d-f/index.html

[providers]: providers/index.md

[OpenSSL]: providers/openssl3.md

[WebCrypto]: providers/webcrypto.md

[CryptoKit]: providers/cryptokit.md

[JDK]: providers/jdk.md

[BOM]: dependencies/bom.md

[Gradle version catalog]: dependencies/gradle-version-catalog.md

[CryptographyProvider]: api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyProvider.Default]: api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/-companion/-default.html

[CryptographyAlgorithm]: api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html
