# MAC

A Message Authentication Code (MAC) produces a short, fixed-size tag from a message and a secret key.
The tag proves both **integrity** (the message was not modified) and **authenticity** (it was created by someone who holds the key).
Unlike a plain hash, only a party with the correct key can generate or verify the tag.

!!! note "Assumed imports"

    All code examples on this page assume the following imports and provider setup:

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Generate an HMAC key, sign a message, and verify the tag:

```kotlin
val hmac = provider.get(HMAC)
val key = hmac.keyGenerator(SHA256).generateKey()

// Generate a MAC tag (called "signature" in the API)
val signature = key.signatureGenerator().generateSignature(
    "Hello, World!".encodeToByteArray()
)

// Verify -- throws if the signature is invalid
key.signatureVerifier().verifySignature(
    "Hello, World!".encodeToByteArray(),
    signature
)
```

There are two ways to verify the signature:

- [`verifySignature`][verifySignature] throws an exception on failure.
- [`tryVerifySignature`][tryVerifySignature] returns `true` or `false`.

```kotlin
// Option 1: throws on failure
key.signatureVerifier().verifySignature(data, signature)

// Option 2: Boolean result
val isValid = key.signatureVerifier().tryVerifySignature(data, signature)
```

Both [`signatureGenerator`][SignatureGenerator] and [`signatureVerifier`][SignatureVerifier] return reusable objects -- create them once and
call [`generateSignature`][generateSignature] or [`verifySignature`][verifySignature] as many times as needed.

For larger data, the overload that accepts a [`RawSource`][RawSource] from [kotlinx-io] could be used instead:

```kotlin
val source: RawSource = ... // file, network stream, etc.
val signature = key.signatureGenerator().generateSignature(source)
key.signatureVerifier().verifySignature(source, signature)
```

## Pass-Through

Use [`updatingSource`][updatingSource] or [`updatingSink`][updatingSink] to compute a MAC as data flows through
a [kotlinx-io] pipeline:

```kotlin
val signFunction = key.signatureGenerator().createSignFunction()

// Wrap a source -- data passes through AND is fed into the MAC
val macSource: RawSource = signFunction.updatingSource(dataSource)

// Read all data (it goes to both the consumer and the MAC)
val data = macSource.readByteArray()

// After reading, the signature is ready
val signature = signFunction.signToByteArray()
```

Both [`SignFunction`][SignFunction] and [`VerifyFunction`][VerifyFunction] implement [`AutoCloseable`][AutoCloseable] and support [
`reset`][reset] for a reuse. After finalization, call [`close`][close], or wrap it in a [`use`][use] block:

```kotlin
val signFunction = key.signatureGenerator().createSignFunction().use { hf ->
    // ... feed data to function
    hf.signToByteArray()
}
```

For the most control, use [`update`][update] directly to feed data in arbitrary chunks:

```kotlin
val signFunction = key.signatureGenerator().createSignFunction()

signFunction.update("chunk1".encodeToByteArray())
signFunction.update("chunk2".encodeToByteArray())

val signature = signFunction.signToByteArray()
```

Incremental verification works the same way:

```kotlin
val verifyFunction = key.signatureVerifier().createVerifyFunction()

verifyFunction.update("chunk1".encodeToByteArray())
verifyFunction.update("chunk2".encodeToByteArray())

verifyFunction.verify(signature) // throws on failure
```

## Supported Algorithms

--8<-- "operations/mac.md"

[SignatureGenerator]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/index.html

[generateSignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/generate-signature.html

[SignatureVerifier]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/index.html

[verifySignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/verify-signature.html

[tryVerifySignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/try-verify-signature.html

[SignFunction]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-sign-function/index.html

[VerifyFunction]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-verify-function/index.html

[reset]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/reset.html

[update]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/update.html

[updatingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/updating-source.html

[updatingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/updating-sink.html

[AutoCloseable]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-auto-closeable/

[use]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/use.html

[close]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-auto-closeable/close.html

[RawSource]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-source/

[kotlinx-io]: https://github.com/Kotlin/kotlinx-io
