# Module cryptography-binary

Provides an ability to create in-memory holder of binary data from different formats: text, bytes, hex, base64.

> The module is currently experimental and is subject to API/ABI changes

## Example

```kotlin
val data = BinaryData.fromUtf8String("Hello world")

val hex = data.toHexString()

println(hex)

val dataFromHex = BinaryData.fromHexString(hex)

val text = hex.toUtf8String()

println(text)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-binary:0.3.1")
}
```

# Package dev.whyoleg.cryptography.binary

Provides an ability to create in-memory holder of binary data from different formats: text, bytes, hex, base64.
