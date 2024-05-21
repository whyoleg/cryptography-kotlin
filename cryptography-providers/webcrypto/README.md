# Module cryptography-provider-webcrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* only `suspend` functions are supported, because `WebCrypto` API is async by default
* AES.* (browser only): may not support `192 bit` keys
* AES.CBC: only `padding=true` is supported
* ECDSA: only `RAW` signature format is supported
* ECDSA (browser only): private key `DER` encoding can be different comparing to other providers
  (but it will still work)

## Example

```kotlin
val provider = CryptographyProvider.WebCrypto // or CryptographyProvider.Default

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-webcrypto:0.3.1")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives

# Package dev.whyoleg.cryptography.providers.webcrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[WebCrypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives
