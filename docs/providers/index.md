# Providers

At the current moment, the following providers are available out of the box:

* [JDK](jdk.md) - via
  JDK built-in [JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
* [WebCrypto](webcrypto.md) - via
  [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* [Apple](apple.md) - via
  [CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html)
* [CryptoKit](cryptokit.md) - via
  [CryptoKit](https://developer.apple.com/documentation/cryptokit/)
* [OpenSSL3](openssl3.md) - via [OpenSSL 3.x](https://www.openssl.org),
  statically linked to prebuilt OpenSSL 3.3.2 or dynamically linked (experimental)

## Optimal provider

While the library is overall multiplatform and all algorithm/operation interfaces are available on all targets,
support for a specific algorithm for a specific target depends on the used provider.
Still, most of the popular algorithms are supported by providers, with minimal dependencies.
That's why a library provides a specific dependency called `optimal` provider: it doesn't implement any new algorithms, but allows to use it
as a single dependency with best-fit preconfigured providers per target:

* js, wasmJs: [WebCrypto](webcrypto.md) provider will be used
* jvm: [JDK](jdk.md) provider with an ability to use [custom security providers](jdk.md#custom-java-providers)
  like [BouncyCastle](https://www.bouncycastle.org)
* ios, macos, watchos, tvos: [CryptoKit](cryptokit.md) provider with the fallback to [Apple](apple.md)
* linux, mingw, androidNative: [OpenSSL3](openssl3.md) provider will be used

To use `optimal` provider just add the following dependency for any target/platform/source-set:

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.5.0")
}
```

## Supported primitives

Below there are several tables that show what is supported and what is not
(I know that it's not the easiest thing to understand... But we have what we have).

For additional limitation please consult provider specific documentation.

### Supported targets per provider

| Target                                                                                        | jdk | webcrypto | apple | cryptokit                 | openssl3        |
|-----------------------------------------------------------------------------------------------|-----|-----------|-------|---------------------------|-----------------|
| jvm                                                                                           | ✅   | ➖         | ➖     | ➖                         | ❌               |
| js                                                                                            | ➖   | ✅         | ➖     | ➖                         | ❌               |
| wasmJs                                                                                        | ➖   | ✅         | ➖     | ➖                         | ❌               |
| wasmWasi                                                                                      | ➖   | ➖         | ➖     | ➖                         | ❌               |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64                                                     | ➖   | ➖         | ✅     | ✅                         | ✅ prebuilt only |
| watchosX64<br/>watchosArm32<br/>watchosArm64<br/>watchosSimulatorArm64<br/>watchosDeviceArm64 | ➖   | ➖         | ✅     | ✅ (except `watchosArm32`) | ✅ prebuilt only |
| tvosX64<br/>tvosArm64<br/>tvosSimulatorArm64                                                  | ➖   | ➖         | ✅     | ✅                         | ✅ prebuilt only |
| macosX64<br/>macosArm64                                                                       | ➖   | ➖         | ✅     | ✅                         | ✅               |
| linuxX64<br/>linuxArm64                                                                       | ➖   | ➖         | ➖     | ➖                         | ✅               |
| mingwX64                                                                                      | ➖   | ➖         | ➖     | ➖                         | ✅               |
| androidNativeX64<br/>androidNativeX86<br/>androidNativeArm64<br/>androidNativeArm32           | ➖   | ➖         | ➖     | ➖                         | ✅ prebuilt only |

> ✅ : supported
>
> ➖ : not applicable
>
> ❌ : not supported (yet?)

### Supported algorithms per provider

> `supported` here means that those algorithms are tested and works at least in some configuration
> (f.e. different Java versions or Java providers can have different algorithms supported)

| Operation                                   | Algorithm        | jdk | webcrypto | apple | cryptokit | openssl3 |
|---------------------------------------------|------------------|:---:|:---------:|:-----:|-----------|:--------:|
| **Digest**                                  | ⚠️ MD5           |  ✅  |     ❌     |   ✅   | ✅         |    ✅     |
|                                             | ⚠️ SHA1          |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA224           |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | SHA256           |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA384           |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA512           |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | SHA3 family      |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
|                                             | ⚠️ RIPEMD160     |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
| **MAC**                                     | HMAC             |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | CMAC             |  ✅  |     ❌     |   ❌   | ❌         |    ✅     |
| **Symmetric-key<br/>encryption/decryption** | AES-CBC          |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | AES-CFB8         |  ✅  |     x     |   ✅   | ❌         |    ✅     |
|                                             | AES-CTR          |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | AES-GCM          |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
|                                             | ⚠️ AES-ECB       |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
| **Public-key<br/>encryption/decryption**    | RSA-OAEP         |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ RSA-PKS1-v1_5 |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
|                                             | ⚠️ RSA-RAW       |  ✅  |     ❌     |   ✅   | ❌         |    ✅     |
| **Digital Signatures**                      | ECDSA            |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |
|                                             | RSA-SSA-PSS      |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | RSA-PKS1-v1_5    |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
| **Key Agreement**                           | ECDH             |  ✅  |     ✅     |   ❌   | ✅         |    ✅     |
| **PRF/KDF**                                 | PBKDF2           |  ✅  |     ✅     |   ✅   | ❌         |    ✅     |
|                                             | HKDF             |  ✅  |     ✅     |   ✅   | ✅         |    ✅     |

> ⚠️ : use carefully
>
> ✅ : supported
>
> ❌ : not supported (yet?)
