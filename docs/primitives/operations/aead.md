# AEAD

Authenticated Encryption with Associated Data (AEAD) provides confidentiality and integrity in a
single operation. Every ciphertext carries an authentication tag -- if anyone tampers with the
data, decryption fails immediately with an exception rather than silently producing garbage.

!!! note "Assumed imports"

    All examples assume the following:

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Get the algorithm, generate a key, create a [`cipher`][IvAuthenticatedCipher], and [`encrypt`][encrypt]/[`decrypt`][decrypt]:

```kotlin
val aesGcm = provider.get(AES.GCM)
val key = aesGcm.keyGenerator().generateKey()
val cipher = key.cipher()

// Encrypt
val ciphertext = cipher.encrypt(plaintext = "secret message".encodeToByteArray())

// Decrypt
val plaintext = cipher.decrypt(ciphertext = ciphertext)
println(plaintext.decodeToString()) // secret message
```

Each call to [`encrypt`][encrypt] generates a fresh random IV and prepends it to the output:
`[IV | ciphertext | tag]`. When you pass this to [`decrypt`][decrypt], the library splits it
automatically. The cipher object is reusable -- call [`encrypt`][encrypt] and [`decrypt`][decrypt] on it as many times as needed.

## Associated Data

Associated data (AAD) is authenticated but not encrypted. Use it to bind ciphertext to a context
so it cannot be replayed elsewhere:

```kotlin
val cipher = key.cipher()
val userId = "user-123".encodeToByteArray()

// Encrypt with associated data
val ciphertext = cipher.encrypt(
    plaintext = "secret".encodeToByteArray(),
    associatedData = userId
)

// Decrypt -- must provide the same associated data
val plaintext = cipher.decrypt(
    ciphertext = ciphertext,
    associatedData = userId
)
```

If you provide different associated data at decryption -- or omit it entirely -- the
authentication tag will not match and decryption throws an exception. The associated data itself
is never included in the ciphertext output; both sides must know it independently.

## Custom IV

By default, a random IV is generated and prepended to the ciphertext. If your protocol requires
a specific IV handling, use [`encryptWithIv`][encryptWithIv]
and [`decryptWithIv`][decryptWithIv]:

```kotlin
val cipher = key.cipher()
val iv = ByteArray(12) // 12 bytes for AES-GCM

val ciphertext = cipher.encryptWithIv(
    iv = iv,
    plaintext = "secret".encodeToByteArray()
)

// With custom IV, the output does NOT contain the IV -- only [ciphertext | tag]
val plaintext = cipher.decryptWithIv(
    iv = iv,
    ciphertext = ciphertext
)
```

!!! warning

    Reusing an IV with the same key completely breaks AES-GCM security. Only use custom IVs
    when you have a reliable mechanism to guarantee uniqueness.

## Streaming

For large data that does not fit in memory, use the [kotlinx-io] streaming API.
The [`cipher`][IvAuthenticatedCipher] provides an ability to transform [`RawSource`][RawSource] via
[`encryptingSource`][encryptingSource] and [`decryptingSource`][decryptingSource]
as well as [`RawSink`][RawSink] with [`encryptingSink`][encryptingSink] and [`decryptingSink`][decryptingSink]:

```kotlin
val cipher = key.cipher()
val aad = "context".encodeToByteArray()

// Pull-based: wrap a source
val encryptedSource: RawSource = cipher.encryptingSource(plaintextSource, associatedData = aad)
val decryptedSource: RawSource = cipher.decryptingSource(ciphertextSource, associatedData = aad)

// Push-based: wrap a sink
val encryptingSink: RawSink = cipher.encryptingSink(destinationSink, associatedData = aad)
val decryptingSink: RawSink = cipher.decryptingSink(plaintextSink, associatedData = aad)
```

Custom IV variants are also available: [`encryptingSourceWithIv`][encryptingSourceWithIv],
[`encryptingSinkWithIv`][encryptingSinkWithIv], [`decryptingSourceWithIv`][decryptingSourceWithIv],
[`decryptingSinkWithIv`][decryptingSinkWithIv].

## Supported Algorithms

--8<-- "operations/aead.md"

[IvAuthenticatedCipher]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-cipher/index.html

[encrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/encrypt.html

[encryptWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-encryptor/encrypt-with-iv.html

[encryptingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/encrypting-source.html

[encryptingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-encryptor/encrypting-sink.html

[encryptingSourceWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-encryptor/encrypting-source-with-iv.html

[encryptingSinkWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-encryptor/encrypting-sink-with-iv.html

[decrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/decrypt.html

[decryptWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-decryptor/decrypt-with-iv.html

[decryptingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/decrypting-source.html

[decryptingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-authenticated-decryptor/decrypting-sink.html

[decryptingSourceWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-decryptor/decrypting-source-with-iv.html

[decryptingSinkWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-authenticated-decryptor/decrypting-sink-with-iv.html

[RawSource]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-source/

[RawSink]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-sink/

[kotlinx-io]: https://github.com/Kotlin/kotlinx-io
