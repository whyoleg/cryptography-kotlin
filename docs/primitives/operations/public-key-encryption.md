# Public-Key Encryption

Public-key (asymmetric) encryption uses a key pair: anyone can encrypt with the public key, but only the holder of the
corresponding private key can decrypt. This makes it possible to receive encrypted messages without sharing a secret in
advance.

!!! note "Assumed imports"

    All examples on this page assume the following imports and setup:

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*
    import dev.whyoleg.cryptography.BinarySize.Companion.bits

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Generate a key pair, encrypt with the public key, and decrypt with the private key:

```kotlin
val algorithm = provider.get(RSA.OAEP)

// Generate a 3072-bit RSA key pair
val keyPair = algorithm.keyPairGenerator(3072.bits).generateKey()

// Encrypt with the public key
val ciphertext = keyPair.publicKey.encryptor()
    .encrypt("secret".encodeToByteArray())

// Decrypt with the private key
val plaintext = keyPair.privateKey.decryptor()
    .decrypt(ciphertext)

println(plaintext.decodeToString()) // secret
```

The [`encryptor`][AuthenticatedEncryptor] and [`decryptor`][AuthenticatedDecryptor]
methods return reusable objects -- create them once and call [`encrypt`][encrypt] or [`decrypt`][decrypt] repeatedly for multiple messages.

## Plaintext Size Limits

RSA can only encrypt data up to a size determined by the key size and digest. For example, a 3072-bit key with SHA-256
can encrypt at most 318 bytes. Attempting to exceed this limit causes a runtime error.

For larger payloads, use hybrid encryption: encrypt the data with a symmetric algorithm (e.g., AES-GCM), then encrypt
only the symmetric key with RSA-OAEP. This is the standard approach used by TLS, PGP, and most real-world protocols.
See [Hybrid Encryption](../recipes/hybrid-encryption.md) for a worked example.

## Associated Data (OAEP Label)

RSA-OAEP supports an optional label (exposed as `associatedData`) that is bound into the ciphertext. The same label must
be provided during both encryption and decryption. If omitted, an empty label is used.

```kotlin
val algorithm = provider.get(RSA.OAEP)
val keyPair = algorithm.keyPairGenerator(3072.bits).generateKey()

val label = "context-id".encodeToByteArray()

val ciphertext = keyPair.publicKey.encryptor()
    .encrypt("secret".encodeToByteArray(), associatedData = label)

val plaintext = keyPair.privateKey.decryptor()
    .decrypt(ciphertext, associatedData = label)
```

Most applications leave the label empty. It is useful when you need to ensure ciphertext produced for one context cannot
be decrypted in another.

## Supported Algorithms

--8<-- "operations/public-key-encryption.md"

[AuthenticatedEncryptor]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/index.html

[AuthenticatedDecryptor]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/index.html

[encrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/encrypt.html

[decrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/decrypt.html

[generateKey]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-key-generator/generate-key.html
