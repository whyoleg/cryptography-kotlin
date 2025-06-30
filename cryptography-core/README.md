# Module cryptography-core

Provides multiplatform API to build, get and use cryptography primitives

Core entities:

* [CryptographyProvider][CryptographyProvider] provides a way to get specific [CryptographyAlgorithm][CryptographyAlgorithm] by its id
* [CryptographyProvider.Default][CryptographyProvider.Default] is the default provider
  which is just a link to the first registered provider.
  After adding dependency to provider (like openssl3) it will be automatically registered as default
* inheritors of [CryptographyAlgorithm][CryptographyAlgorithm] (like f.e. [AES][AES]) provides access to operations (like
  f.e. [cipher][cipher])

## Example

```kotlin
CryptographyProvider.Default
    .get(SHA512)
    .hasher()
    .hash("Kotlin is Awesome".encodeToByteArray())
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-core:0.4.0")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyProvider.Default]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/-default/index.html

[CryptographyAlgorithm]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-a-e-s/index.html

[cipher]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-cipher/index.html
