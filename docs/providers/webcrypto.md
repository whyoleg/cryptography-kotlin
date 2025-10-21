# WebCrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via [WebCrypto][WebCrypto]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* only `suspend` functions are supported, because `WebCrypto` API is async by default
* AES.* (browser only): may not support `192 bit` keys
* AES.CBC: only `padding=true` is supported
* EdDSA/XDH were added later to WebCrypto and might not be available in all browsers (https://github.com/w3c/webcrypto/pull/362)

## Example

```kotlin
val provider = CryptographyProvider.WebCrypto // or CryptographyProvider.Default

// get some algorithm
provider.get(SHA512)
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
 
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748
