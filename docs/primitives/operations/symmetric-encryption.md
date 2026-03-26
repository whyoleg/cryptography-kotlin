# Symmetric Encryption

Symmetric encryption uses a single shared key to encrypt and decrypt data. The modes on this page --
AES-CBC, AES-CTR, and AES-ECB -- provide **confidentiality only**. They do not detect tampering or verify
integrity of the ciphertext.

!!! warning "Prefer AEAD for new applications"

    For most use cases, [AEAD](aead.md) algorithms like AES-GCM provide both encryption **and** authentication.
    Use the modes on this page only when a protocol or legacy system requires them.

!!! note "Assumed imports"

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Get the algorithm, generate a key, create a [`cipher`][IvCipher], and [`encrypt`][encrypt]/[`decrypt`][decrypt]. AES-CBC enables PKCS#7
padding by default, so plaintext of any length is accepted:

```kotlin
val aesCbc = provider.get(AES.CBC)
val key = aesCbc.keyGenerator().generateKey()
val cipher = key.cipher() // padding enabled by default

// Encrypt
val ciphertext = cipher.encrypt(plaintext = "secret message".encodeToByteArray())

// Decrypt
val plaintext = cipher.decrypt(ciphertext = ciphertext)
println(plaintext.decodeToString()) // secret message
```

Each call to [`encrypt`][encrypt] generates a fresh random IV and prepends it to the output: `[IV | ciphertext]`.
When you pass this to [`decrypt`][decrypt], the library splits it automatically.
The cipher is reusable -- call [`encrypt`][encrypt] and [`decrypt`][decrypt] as many times as needed.

To disable padding (plaintext must then be a multiple of 16 bytes):

```kotlin
val cipher = key.cipher(padding = false)
```

## Custom IV

By default, a random IV is generated and prepended to the ciphertext. If your protocol requires
a specific IV, use [`encryptWithIv`][encryptWithIv] and [`decryptWithIv`][decryptWithIv]:

```kotlin
val cipher = key.cipher()
val iv = ByteArray(16) // 16 bytes for AES-CBC

val ciphertext = cipher.encryptWithIv(
    iv = iv,
    plaintext = "secret".encodeToByteArray()
)

// With custom IV, the output does NOT contain the IV -- only the ciphertext
val plaintext = cipher.decryptWithIv(
    iv = iv,
    ciphertext = ciphertext
)
```

!!! warning

    Reusing an IV with the same key weakens or breaks encryption security depending on the mode.
    Only use custom IVs when you have a reliable mechanism to guarantee uniqueness.

## Streaming

For large data that does not fit in memory, use the [kotlinx-io] streaming API.
The [`cipher`][IvCipher] provides an ability to transform [`RawSource`][RawSource] via
[`encryptingSource`][encryptingSource] and [`decryptingSource`][decryptingSource]
as well as [`RawSink`][RawSink] with [`encryptingSink`][encryptingSink] and [`decryptingSink`][decryptingSink]:

```kotlin
val cipher = key.cipher()

// Pull-based: wrap a source
val encryptedSource: RawSource = cipher.encryptingSource(plaintextSource)
val decryptedSource: RawSource = cipher.decryptingSource(ciphertextSource)

// Push-based: wrap a sink
val encryptingSink: RawSink = cipher.encryptingSink(destinationSink)
val decryptingSink: RawSink = cipher.decryptingSink(plaintextSink)
```

Custom IV variants are also available: [`encryptingSourceWithIv`][encryptingSourceWithIv],
[`encryptingSinkWithIv`][encryptingSinkWithIv], [`decryptingSourceWithIv`][decryptingSourceWithIv],
[`decryptingSinkWithIv`][decryptingSinkWithIv].

## Supported Algorithms

--8<-- "operations/symmetric-encryption.md"

[IvCipher]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-cipher/index.html

[encrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-encryptor/encrypt.html

[encryptWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-encryptor/encrypt-with-iv.html

[encryptingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-encryptor/encrypting-source.html

[encryptingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-encryptor/encrypting-sink.html

[encryptingSourceWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-encryptor/encrypting-source-with-iv.html

[encryptingSinkWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-encryptor/encrypting-sink-with-iv.html

[decrypt]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-decryptor/decrypt.html

[decryptWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-decryptor/decrypt-with-iv.html

[decryptingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-decryptor/decrypting-source.html

[decryptingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-decryptor/decrypting-sink.html

[decryptingSourceWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-decryptor/decrypting-source-with-iv.html

[decryptingSinkWithIv]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-iv-decryptor/decrypting-sink-with-iv.html

[generateKey]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-key-generator/generate-key.html

[RawSource]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-source/

[RawSink]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-sink/

[kotlinx-io]: https://github.com/Kotlin/kotlinx-io
