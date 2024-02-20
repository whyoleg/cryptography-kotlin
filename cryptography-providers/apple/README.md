# Module cryptography-provider-apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

For supported targets and algorithms, please consult [Supported primitives section][Supported primitives section]

## Limitations

* KeyFormat: doesn't support `JWK` key format yet

## Example

```kotlin
val provider = CryptographyProvider.Apple // or CryptographyProvider.Default 

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-provider-apple:0.3.0")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives

# Package dev.whyoleg.cryptography.providers.apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via [CommonCrypto][CommonCrypto]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CommonCrypto]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html

[Supported primitives section]: https://whyoleg.github.io/cryptography-kotlin/providers#supported-primitives
