# WebCrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* only `suspend` functions are supported, because `WebCrypto` API is async by default
* AES.* (browser only): may not support `192 bit` keys
* AES.CBC: only `padding=true` is supported
* EdDSA/XDH availability depends on the engine:
  - Node.js, Firefox, Safari: supported (Ed25519/Ed448, X25519/X448)
  - Chromium-based (Chrome/Edge/Opera): requires enabling experimental web platform features; otherwise not exposed by the provider

## Example

```kotlin
// default provider
val provider = CryptographyProvider.WebCrypto // or CryptographyProvider.Default

// get some algorithm
provider.get(SHA512)
```

To opt-in to EdDSA/XDH on Chromium-based engines (with experimental web platform features enabled),
explicitly enable experimental Edwards algorithms:

```kotlin
val provider = CryptographyProvider.WebCrypto(enableExperimentalEdwards = true)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-webcrypto:0.5.0")
}
```

[CryptographyProvider]: ../api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

[Supported primitives section]: index.md#supported-primitives
