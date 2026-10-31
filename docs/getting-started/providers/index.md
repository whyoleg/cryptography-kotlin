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

## When something isn't supported

Providers don't support the same set of algorithms and parameters, and support can also depend on the platform version.
Depending on what is not supported, it's reported in one of the following ways:

* **Algorithm**: `provider.getOrNull(AES.GCM)` returns `null`, and `provider.get(AES.GCM)` throws an exception.
* **Parameter** (curve, digest, key or parameter sizes): the method receiving the parameter throws an exception, for example,
  `keyPairGenerator(EC.Curve.secp256k1)`, `keyDecoder(SHA3_256)` or `signatureGenerator(SHA3_256, format)`:
    * `IllegalStateException`, if the value is valid, but can't be used by the provider.
    * `IllegalArgumentException`, if the value is never valid for the algorithm.
    * The JDK provider propagates exceptions thrown by JCA, which are usually subclasses of `GeneralSecurityException`.
* **On first use**: some parameters can't be checked earlier, so they fail only when an operation is performed.
  This applies to tag sizes, the RSA-PSS salt size (it depends on the key), key sizes other than AES ones,
  custom OpenSSL curve names, and some browser-specific WebCrypto cases.

See the [algorithm support tables](../../primitives/operations/index.md) for what is supported by each provider.

## Providers supported by Kotlin targets

| Target                                                        | Available providers                                                                            | Used by `optimal`        |
|---------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------|
| jvm                                                           | [JDK](jdk.md)                                                                                  | JDK                      |
| js                                                            | [WebCrypto](webcrypto.md)                                                                      | WebCrypto                |
| wasmJs                                                        | [WebCrypto](webcrypto.md)                                                                      | WebCrypto                |
| wasmWasi                                                      | —                                                                                              | —                        |
| iosX64<br/>iosSimulatorArm64<br/>iosArm64                     | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only) | CryptoKit + CommonCrypto |
| tvosArm64<br/>tvosSimulatorArm64                              | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only) | CryptoKit + CommonCrypto |
| watchosArm64<br/>watchosSimulatorArm64<br/>watchosDeviceArm64 | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md) (prebuilt only) | CryptoKit + CommonCrypto |
| macosArm64                                                    | [CryptoKit](apple.md)<br/>[CommonCrypto](apple.md)<br/>[OpenSSL3](openssl3.md)                 | CryptoKit + CommonCrypto |
| linuxX64<br/>linuxArm64                                       | [OpenSSL3](openssl3.md)                                                                        | OpenSSL3 (prebuilt)      |
| mingwX64                                                      | [OpenSSL3](openssl3.md)                                                                        | OpenSSL3 (prebuilt)      |

For a full list of supported algorithms per provider, see [Operations](../../primitives/operations/index.md).
