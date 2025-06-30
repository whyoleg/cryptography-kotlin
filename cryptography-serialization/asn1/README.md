# Module cryptography-serialization-asn1

ASN.1/[DER][DER]: binary serialization of ASN.1/DER content via [kotlinx.serialization][kotlinx.serialization]

> The module is currently experimental and is subject to API/ABI changes

## Example

```kotlin
@Serializable
class SimpleAlgorithmIdentifier(
    val algorithm: ObjectIdentifier,
    val parameters: Nothing?,
)

val algorithm = SimpleAlgorithmIdentifier(ObjectIdentifier("1.2.840.113549.1.1.11"), null)

// encoding
val bytes = DER.encodeToByteArray(algorithm)

println(bytes.toHexString()) // prints "300d06092a864886f70d01010b0500"

// decoding
val decoded = DER.decodeFromByteArray<SimpleAlgorithmIdentifier>(bytes)

println(decoded.algorithm.value) // prints "1.2.840.113549.1.1.11"
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-serialization-asn1:0.4.0")
}
```

[DER]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1/dev.whyoleg.cryptography.serialization.asn1/-d-e-r/index.html

[kotlinx.serialization]: https://github.com/Kotlin/kotlinx.serialization
