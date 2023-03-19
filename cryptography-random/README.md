# Module cryptography-random

Zero-dependency platform-dependent CSPRNG exposed via kotlin.Random API.
object `CryptographyRandom.Default` is the default platform dependent instance of `CryptographyRandom`.

## Example

```kotlin
val bytes = CryptographyRandom.nextBytes(20)
```

## Using in your projects

```kotlin
dependencies {
    implementation("dev.whyoleg.cryptography:cryptography-random:0.1.0")
}
```

# Package dev.whyoleg.cryptography.random

Zero-dependency platform-dependent CSPRNG exposed via kotlin.Random API
