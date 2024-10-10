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

# Package dev.whyoleg.cryptography

Provides core primitives for creating and accessing [CryptographyAlgorithm][CryptographyAlgorithm]
and [CryptographyProvider][CryptographyProvider]

[CryptographyProvider]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-provider/index.html

[CryptographyAlgorithm]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography/-cryptography-algorithm/index.html

# Package dev.whyoleg.cryptography.algorithms

Provides common algorithms:

* digests (e.g [SHA256][SHA256] and [SHA512][SHA512])
* symmetric ciphers ([AES][AES])
* asymmetric encryption and signature ([RSA][RSA] and [ECDSA][ECDSA])
* MAC ([HMAC][HMAC])
* Key derivation ([PBKDF2][PBKDF2] and [HKDF][HKDF])
* Key agreement ([ECDH][ECDH])

[SHA256]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-s-h-a256/index.html

[SHA512]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-s-h-a512/index.html

[AES]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-a-e-s/index.html

[HMAC]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-m-a-c/index.html

[RSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-r-s-a/index.html

[ECDSA]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-s-a/index.html

[ECDH]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-e-c-d-h/index.html

[PBKDF2]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-p-b-k-d-f2/index.html

[HKDF]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.algorithms/-h-k-d-f/index.html

# Package dev.whyoleg.cryptography.operations

Provides APIs to perform cryptography operations:

* [hashing][Hasher]
* [encryption][Encryptor]/[decryption][Decryptor] and
  Authenticated [encryption][AuthenticatedEncryptor]/[decryption][AuthenticatedDecryptor]
* signature [verification][SignatureVerifier] and [generation][SignatureGenerator]
* [secret derivation][SecretDerivation] (KDF/PRF) and [shared secret derivation][SharedSecretDerivation] (Key agreement)

[Encryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-encryptor/index.html

[Decryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-decryptor/index.html

[AuthenticatedEncryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/index.html

[AuthenticatedDecryptor]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/index.html

[Hasher]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-hasher/index.html

[SignatureVerifier]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/index.html

[SignatureGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/index.html

[SecretDerivation]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-secret-derivation/index.html

[SharedSecretDerivation]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.operations/-shared-secret-derivation/index.html

# Package dev.whyoleg.cryptography.materials.key

Provides API for working with keys: [encoding][EncodableKey], [decoding][KeyDecoder] and [generation][KeyGenerator]

[EncodableKey]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-encodable-key/index.html

[KeyDecoder]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-decoder/index.html

[KeyGenerator]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-core/dev.whyoleg.cryptography.materials.key/-key-generator/index.html
