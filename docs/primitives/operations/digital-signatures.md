# Digital Signatures

Digital signatures use a key pair to provide authentication and integrity.
The private key signs a message, producing a signature that anyone with the corresponding public key can verify.
This proves both who produced the data and that it has not been tampered with.

!!! note "Assumed imports"

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Generate a key pair, sign a message, and verify the signature using ECDSA with P-256:

```kotlin
val ecdsa = provider.get(ECDSA)
val keyPair = ecdsa.keyPairGenerator(EC.Curve.P256).generateKey()

// Sign a message with the private key
val message = "Transfer 100 EUR to Alice".encodeToByteArray()
val signature = keyPair.privateKey
    .signatureGenerator(digest = SHA256, format = ECDSA.SignatureFormat.DER)
    .generateSignature(message)

// Verify -- throws if the signature is invalid
keyPair.publicKey
    .signatureVerifier(digest = SHA256, format = ECDSA.SignatureFormat.DER)
    .verifySignature(message, signature)
```

There are two ways to verify the signature:

- [`verifySignature`][verifySignature] throws an exception on failure.
- [`tryVerifySignature`][tryVerifySignature] returns `true` or `false`.

```kotlin
val verifier = keyPair.publicKey
    .signatureVerifier(digest = SHA256, format = ECDSA.SignatureFormat.DER)

// Option 1: throws on failure
verifier.verifySignature(message, signature)

// Option 2: Boolean result
val isValid = verifier.tryVerifySignature(message, signature)
```

Both [`signatureGenerator`][SignatureGenerator] and [`signatureVerifier`][SignatureVerifier] return reusable objects -- create them once and
call [`generateSignature`][generateSignature] or [`verifySignature`][verifySignature] as many times as needed.

For larger data, the overload that accepts a [`RawSource`][RawSource] from [kotlinx-io] could be used instead:

```kotlin
val source: RawSource = ... // file, network stream, etc.
val signature = keyPair.privateKey
    .signatureGenerator(digest = SHA256, format = ECDSA.SignatureFormat.DER)
    .generateSignature(source)
keyPair.publicKey
    .signatureVerifier(digest = SHA256, format = ECDSA.SignatureFormat.DER)
    .verifySignature(source, signature)
```

## Pass-Through

Use [`updatingSource`][updatingSource] or [`updatingSink`][updatingSink] to compute a signature as data flows through
a [kotlinx-io] pipeline:

```kotlin
val signFunction = keyPair.privateKey
    .signatureGenerator(SHA256, ECDSA.SignatureFormat.DER)
    .createSignFunction()

// Wrap a source -- data passes through AND is fed into the signature
val signingSource: RawSource = signFunction.updatingSource(messageSource)

// Read all data (it goes to both the consumer and the signature function)
val data = signingSource.readByteArray()

// After reading, the signature is ready
val signature = signFunction.signToByteArray()
```

Both [`SignFunction`][SignFunction] and [`VerifyFunction`][VerifyFunction] implement [`AutoCloseable`][AutoCloseable] and support [
`reset`][reset] for a reuse. After finalization, call [`close`][close], or wrap it in a [`use`][use] block:

```kotlin
val signature = keyPair.privateKey
    .signatureGenerator(SHA256, ECDSA.SignatureFormat.DER)
    .createSignFunction().use { sf ->
        // ... feed data to function
        sf.signToByteArray()
    }
```

For the most control, use [`update`][update] directly to feed data in arbitrary chunks:

```kotlin
val signFunction = keyPair.privateKey
    .signatureGenerator(SHA256, ECDSA.SignatureFormat.DER)
    .createSignFunction()

signFunction.update("first chunk ".encodeToByteArray())
signFunction.update("second chunk".encodeToByteArray())

val signature = signFunction.signToByteArray()
```

Incremental verification works the same way:

```kotlin
val verifyFunction = keyPair.publicKey
    .signatureVerifier(SHA256, ECDSA.SignatureFormat.DER)
    .createVerifyFunction()

verifyFunction.update("first chunk ".encodeToByteArray())
verifyFunction.update("second chunk".encodeToByteArray())

verifyFunction.verify(signature) // throws on failure
```

## Supported Algorithms

--8<-- "operations/signing.md"

[SignatureGenerator]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/index.html

[generateSignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/generate-signature.html

[createSignFunction]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-generator/create-sign-function.html

[SignatureVerifier]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/index.html

[verifySignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/verify-signature.html

[tryVerifySignature]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/try-verify-signature.html

[createVerifyFunction]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-signature-verifier/create-verify-function.html

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
