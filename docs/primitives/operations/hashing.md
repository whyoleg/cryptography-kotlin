# Hashing

Hashing computes a fixed-size fingerprint (called a _digest_) from arbitrary input data. The same input always
produces the same digest, but the process is one-way -- you cannot recover the original data from the hash.
Use hashing for checksums, data integrity verification, and content addressing.

!!! note "Assumed imports"

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Get the algorithm from your provider, obtain a [`Hasher`][Hasher], and call [`hash`][hash]:

```kotlin
val hasher = provider.get(SHA256).hasher()

val digest = hasher.hash("Hello, World!".encodeToByteArray())

// Same input always produces the same digest
val digest2 = hasher.hash("Hello, World!".encodeToByteArray())
println(digest.contentEquals(digest2)) // true
```

The [`Hasher`][Hasher] is reusable -- each [`hash`][hash] call is independent and does not accumulate state.

For larger data, the overload that accepts a [`RawSource`][RawSource] from [kotlinx-io] could be used instead:

```kotlin
val source: RawSource = ... // file, network stream, etc.
val digest = hasher.hash(source)
```

## Pass-Through

Use [`updatingSource`][updatingSource] or [`updatingSink`][updatingSink] to hash data as it flows through
a [kotlinx-io] pipeline. This is useful when you need both the data and its hash -- for example, saving
a file to disk while computing a checksum:

```kotlin
val hashFunction = hasher.createHashFunction()

// Wrap a source -- data passes through AND is fed into the hash
val source: RawSource = ...
val hashingSource: RawSource = hashFunction.updatingSource(source)

// Read all data from hashingSource (it goes to both the consumer and the hash)
val data = hashingSource.readByteArray()

// After reading, the hash is ready
val digest = hashFunction.hashToByteArray()
```

[`HashFunction`][HashFunction] implements [`AutoCloseable`][AutoCloseable] and support [`reset`][reset] for a reuse.
After finalization, call [`close`][close], or wrap it in a [`use`][use] block:

```kotlin
val digest = hasher.createHashFunction().use { hf ->
    // ... feed data to function
    hf.hashToByteArray()
}
```

For the most control, use [`update`][update] directly to feed data in arbitrary chunks:

```kotlin
val hashFunction = hasher.createHashFunction()

hashFunction.update("Hello, ".encodeToByteArray())
hashFunction.update("World!".encodeToByteArray())

val digest = hashFunction.hashToByteArray()
```

The result is identical to hashing the full concatenated input in a single [`hash`][hash] call.

## Supported Algorithms

--8<-- "operations/hashing.md"

[Hasher]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-hasher/index.html

[hash]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-hasher/hash.html

[HashFunction]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-hash-function/index.html

[reset]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/reset.html

[update]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/update.html

[updatingSource]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/updating-source.html

[updatingSink]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-update-function/updating-sink.html

[AutoCloseable]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-auto-closeable/

[use]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/use.html

[close]: https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-auto-closeable/close.html

[RawSource]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-core/kotlinx.io/-raw-source/

[kotlinx-io]: https://github.com/Kotlin/kotlinx-io
