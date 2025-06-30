# PEM

[PEM][PEM]: encoding/decoding of PEM content from/to [String][String] or [ByteArray][ByteArray]

> PEM functionality is currently experimental and is subject to API/ABI changes

## Example

```kotlin
val encodedPemContent: String = PEM.encode(
    PemContent(
        label = PemLabel("KEY"),
        bytes = "Hello World".encodeToByteArray()
    )
)

println(encodedPemContent)

val decodedPemContent: PemContent = PEM.decode(
    """
    -----BEGIN UNKNOWN-----
    SGVsbG8gV29ybGQ=
    -----END UNKNOWN-----
    
    """.trimIndent(),
)

println(decodedPemContent.bytes.decodeToString()) // prints "Hello World"
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-serialization-pem:0.5.0")
}
```

[PEM]: ../api/cryptography-serialization-pem/dev.whyoleg.cryptography.serialization.pem/-pem/index.html

[String]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/

[ByteArray]: https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/
