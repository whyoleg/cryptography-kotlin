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
    implementation("dev.whyoleg.cryptography:cryptography-core:0.2.0")
}
```

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyProvider.Default]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/-default/index.html

[CryptographyAlgorithm]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.symmetric/-a-e-s/index.html

[cipher]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/-cipher/index.html

# Package dev.whyoleg.cryptography

Provides core primitives for creating and accessing [CryptographyAlgorithm][CryptographyAlgorithm]
and [CryptographyProvider][CryptographyProvider]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyAlgorithm]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html

# Package dev.whyoleg.cryptography.algorithms.digest

Provides common digest algorithms, like [SHA256][SHA256] and [SHA512][SHA512]

[SHA256]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.digest/-s-h-a256/index.html

[SHA512]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.digest/-s-h-a512/index.html

# Package dev.whyoleg.cryptography.algorithms.symmetric

Provides common symmetric ciphers and MAC algorithms, like [AES][AES] and [HMAC][HMAC]

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.symmetric/-a-e-s/index.html

[HMAC]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.symmetric/-h-m-a-c/index.html

# Package dev.whyoleg.cryptography.algorithms.asymmetric

Provides common asymmetric encryption and signature algorithms, like [RSA][RSA] and [ECDSA][ECDSA]

[RSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.asymmetric/-r-s-a/index.html

[ECDSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms.asymmetric/-e-c-d-s-a/index.html

# Package dev.whyoleg.cryptography.operations.cipher

Provides API for [encryption][Encryptor]/[decryption][Decryptor] and
Authenticated [encryption][AuthenticatedEncryptor]/[decryption][AuthenticatedDecryptor]

[Encryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/-encryptor/index.html

[Decryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/-decryptor/index.html

[AuthenticatedEncryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/-authenticated-encryptor/index.html

[AuthenticatedDecryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.cipher/-authenticated-decryptor/index.html

# Package dev.whyoleg.cryptography.operations.hash

Provides [hashing][Hasher] operation

[Hasher]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.hash/-hasher/index.html

# Package dev.whyoleg.cryptography.operations.signature

Provides signature [verification][SignatureVerifier] and [generation][SignatureGenerator] API

[SignatureVerifier]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.signature/-signature-verifier/index.html

[SignatureGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations.signature/-signature-generator/index.html

# Package dev.whyoleg.cryptography.materials.key

Provides API for working with keys: [encoding][EncodableKey], [decoding][KeyDecoder] and [generation][KeyGenerator]

[EncodableKey]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-encodable-key/index.html

[KeyDecoder]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-decoder/index.html

[KeyGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-generator/index.html
