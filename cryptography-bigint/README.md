# Module cryptography-bigint

[BigInt][BigInt]: an arbitrary-precision integer.

> The module is currently experimental and is subject to API/ABI changes

On current moment [BigInt][BigInt] provides only simple operations:

* conversion between primitive number types, [String][String] and [ByteArray][ByteArray] (two's complement)
* comparing [BigInt][BigInt] with itself and other number types
* serialization via [kotlinx.serialization][kotlinx.serialization]

Depending on target/platform uses:

* JVM - [BigInteger](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html)
* JS and WasmJs - [JS BigInt](https://developer.mozilla.org/ru/docs/Web/JavaScript/Reference/Global_Objects/BigInt)
* Native and WasmWasi - implemented from scratch

## Example

```kotlin
val bigInt: BigInt = "1232186768767".toBigInt()

println(bigInt > 0) // prints "true"
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-bigint:0.2.0")
}
```

[BigInt]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-bigint/dev.whyoleg.cryptography.bigint/-big-int/index.html

[String]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/

[ByteArray]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/

[kotlinx.serialization]: https://github.com/Kotlin/kotlinx.serialization

# Package dev.whyoleg.cryptography.bigint

[BigInt][BigInt]: an arbitrary-precision integer.

[BigInt]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-bigint/dev.whyoleg.cryptography.bigint/-big-int/index.html
