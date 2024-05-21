# Module cryptography-serialization-asn1-modules

ASN.1 modules/declarations from different RFCs, f.e.
[SubjectPublicKeyInfo][SubjectPublicKeyInfo] from [RFC5280][RFC5280] and [PrivateKeyInfo][PrivateKeyInfo] from [RFC5208][RFC5208]

> The module is currently experimental and is subject to API/ABI changes

## Example

```kotlin
val rsaPublicKey: ByteArray = TODO("...")

val spkiPublicKey: ByteArray = DER.encodeToByteArray(
    SubjectPublicKeyInfo(ObjectIdentifier.RSA, rsaPublicKey)
)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-serialization-asn1-modules:0.3.1")
}
```

[SubjectPublicKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-subject-public-key-info/index.html

[PrivateKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-private-key-info/index.html

[RFC5280]: https://datatracker.ietf.org/doc/html/rfc5280

[RFC5208]: https://datatracker.ietf.org/doc/html/rfc5208

# Package dev.whyoleg.cryptography.serialization.asn1.modules

ASN.1 modules/declarations from different RFCs, f.e.
[SubjectPublicKeyInfo][SubjectPublicKeyInfo] from [RFC5280][RFC5280] and [PrivateKeyInfo][PrivateKeyInfo] from [RFC5208][RFC5208]

[SubjectPublicKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-subject-public-key-info/index.html

[PrivateKeyInfo]: https://whyoleg.github.io/cryptography-kotlin/api/cryptography-serialization-asn1-modules/dev.whyoleg.cryptography.serialization.asn1.modules/-private-key-info/index.html

[RFC5280]: https://datatracker.ietf.org/doc/html/rfc5280

[RFC5208]: https://datatracker.ietf.org/doc/html/rfc5208
