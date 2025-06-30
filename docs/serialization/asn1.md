# ASN.1/DER

ASN.1/[DER][DER]: binary serialization of ASN.1/DER content via [kotlinx.serialization][kotlinx.serialization].
Additionally, library provides ASN.1 modules/declarations from different RFCs, f.e.
[SubjectPublicKeyInfo][SubjectPublicKeyInfo] from [RFC5280][RFC5280] and [PrivateKeyInfo][PrivateKeyInfo] from [RFC5208][RFC5208]

> ASN.1 functionality is currently experimental and is subject to API/ABI changes

## Example

Defining custom DER serializable class:

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

Using [SubjectPublicKeyInfo][SubjectPublicKeyInfo] coming from `cryptography-serialization-asn1-modules` dependency:

```kotlin
val rsaPublicKey: ByteArray = TODO("...")

val spkiPublicKey: ByteArray = DER.encodeToByteArray(
    SubjectPublicKeyInfo(ObjectIdentifier.RSA, rsaPublicKey)
)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-serialization-asn1:0.5.0")
    implementation("dev.whyoleg.cryptography:cryptography-serialization-asn1-modules:0.5.0")
}
```

[DER]: ../api/cryptography-serialization-asn1/dev.whyoleg.cryptography.serialization.asn1/-der/index.html

[kotlinx.serialization]: https://github.com/Kotlin/kotlinx.serialization

[SubjectPublicKeyInfo]: ../api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-subject-public-key-info/index.html

[PrivateKeyInfo]: ../api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-private-key-info/index.html

[RFC5280]: https://datatracker.ietf.org/doc/html/rfc5280

[RFC5208]: https://datatracker.ietf.org/doc/html/rfc5208
