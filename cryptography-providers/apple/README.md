# Module cryptography-apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via
[CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html).

## Example

```kotlin
val provider = CryptographyProvider.Apple

// get some algorithm
provider.get(SHA512)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-apple:0.1.0")
}
```

# Package dev.whyoleg.cryptography.apple

Provides implementation of [CryptographyProvider][CryptographyProvider] via
[CommonCrypto](https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html).

<!--- MODULE cryptograph-apple -->

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.provider/-cryptography-provider/index.html

<!--- END -->
