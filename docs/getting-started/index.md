# Getting Started

## Prerequisites

Make sure that you use Kotlin 2.3.0+. Using an earlier Kotlin version could still work, but not tested.
The library is published to Maven Central, so make sure that it's added to repositories.

## Add dependencies

Add `cryptography-core` and a [provider](providers/index.md) to your project.
For most users, the `optimal` provider is the right choice — it automatically selects the best provider for each target platform.

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-core:0.5.0")
            implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.5.0")
        }
    }
}
```

For alternative ways to manage dependencies, such as [BOM](dependency-management.md#bom)
or [Gradle version catalog](dependency-management.md#gradle-version-catalog),
see [Dependency Management](dependency-management.md).

## How it works

The library is built around three concepts:

1. A **Provider** (`CryptographyProvider`) connects to a platform-native cryptography implementation
2. From a provider, you get an **Algorithm** (like `AES.GCM` or `ECDSA`) which defines the operations available
3. An algorithm gives you **operations** — key generators, ciphers, hashers, signature generators, etc.

```kotlin
// 1. Get the algorithm from a provider
val aesGcm = CryptographyProvider.Default.get(AES.GCM)
// 2. Generate a key
val key = aesGcm.keyGenerator().generateKey()
// 3. Use operations
val ciphertext = key.cipher().encrypt(plaintext)
```

See [Examples](../examples.md) for more patterns like HMAC, ECDSA signing, and key encoding/decoding.

If the `optimal` provider doesn't cover your needs
(e.g., you need [BouncyCastle](providers/jdk.md#bouncycastle) or a
specific [OpenSSL linking option](providers/openssl3.md#linking-options)),
see [Choosing a Provider](providers/index.md).
