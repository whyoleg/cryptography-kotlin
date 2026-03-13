# Module cryptography-bigint

Arbitrary-precision integer for multiplatform use.

The module provides [BigInt][dev.whyoleg.cryptography.bigint.BigInt] with:

- Conversion between primitive number types, [String][kotlin.String], and [ByteArray][kotlin.ByteArray] (two's complement)
- Comparison with itself and other number types
- Serialization via [kotlinx.serialization](https://github.com/Kotlin/kotlinx.serialization)

Platform implementations:

- JVM: [BigInteger](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html)
- JS, WasmJs: [JS BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt)
- Native, WasmWasi: implemented from scratch

#### [Get complete dependency details at klibs.io](https://klibs.io/package/dev.whyoleg.cryptography/cryptography-bigint)

# Package dev.whyoleg.cryptography.bigint

Arbitrary-precision integer for multiplatform use.
