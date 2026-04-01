# Choosing a Provider

cryptography-kotlin doesn't implement cryptography on its own — it delegates to platform-native libraries
through **providers**. Each provider wraps a specific platform cryptography implementation.

| Provider                               | Platform                                                                                     |
|----------------------------------------|----------------------------------------------------------------------------------------------|
| [JDK](jdk.md)                          | JVM, Android                                                                                 |
| [WebCrypto](webcrypto.md)              | JS, WasmJS                                                                                   |
| [CryptoKit and CommonCrypto](apple.md) | iOS, macOS, tvOS, watchOS                                                                    |
| [OpenSSL3](openssl3.md)                | **static**: iOS, tvOS, watchOS, Android Native<br/>**static & dynamic**: macOS, Linux, MinGW |

For most users, the **optimal provider** is the recommended choice —
it bundles the best-fit provider for each target as a single dependency:

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
}
```

On Apple targets, the optimal provider uses `CryptoKit` first with `CommonCrypto` as a fallback; uses `OpenSSL3`
for other native targets.

## When might you need a specific provider?

You might need to go beyond `optimal` if:

* You need algorithms not available in the default provider for your platform
  (e.g., [SHA3 on JDK 8](jdk.md#bouncycastle) or [secp256k1 curve](jdk.md#bouncycastle))
* You want to use [BouncyCastle](jdk.md#bouncycastle) as the JCA backend for better Android compatibility
* You need a specific [OpenSSL linking strategy](openssl3.md#linking-options) (shared vs. prebuilt)

See the individual provider pages for details on when and how to configure them.

## Providers supported by Kotlin targets

| Target                                                                                        | Available providers                                                                                                    | Used by `optimal`        |
|-----------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|--------------------------|
| jvm                                                                                           | [JDK](jdk.md)                                                                                                          | JDK                      |
| js                                                                                            | [WebCrypto](webcrypto.md)                                                                                              | WebCrypto                |
| wasmJs                                                                                        | [WebCrypto](webcrypto.md)                                                                                              | WebCrypto                |
| wasmWasi                                                                                      | —                                                                                                                      | —                        |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64                                                     | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only)                         | CryptoKit + CommonCrypto |
| tvosX64<br/>tvosArm64<br/>tvosSimulatorArm64                                                  | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only)                         | CryptoKit + CommonCrypto |
| watchosX64<br/>watchosArm32<br/>watchosArm64<br/>watchosSimulatorArm64<br/>watchosDeviceArm64 | [CryptoKit](apple.md) (except `watchosArm32`)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only) | CryptoKit + CommonCrypto |
| macosX64<br/>macosArm64                                                                       | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md)                                         | CryptoKit + CommonCrypto |
| linuxX64<br/>linuxArm64                                                                       | [OpenSSL3](openssl3.md)                                                                                                | OpenSSL3 (prebuilt)      |
| mingwX64                                                                                      | [OpenSSL3](openssl3.md)                                                                                                | OpenSSL3 (prebuilt)      |
| androidNativeX64<br/>androidNativeX86<br/>androidNativeArm64<br/>androidNativeArm32           | [OpenSSL3](openssl3.md) (prebuilt only)                                                                                | OpenSSL3 (prebuilt)      |

For a full list of supported algorithms per provider, see [Operations](../../primitives/operations/index.md).
