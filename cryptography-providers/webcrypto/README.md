# Module cryptography-webcrypto

Provides implementation of [CryptographyProvider][CryptographyProvider] via
[WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

> Notes: only `suspend` functions are supported, because `WebCrypto` API is async by default

## Example

```kotlin
val provider = CryptographyProvider.WebCrypto

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-webcrypto:0.1.0")
}
```

# Package dev.whyoleg.cryptography.webcrypto

<!--- MODULE cryptography-webcrypto -->

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.provider/-cryptography-provider/index.html

<!--- END -->
