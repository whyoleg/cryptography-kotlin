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

If the `optimal` provider doesn't cover your needs
(e.g., you need [BouncyCastle](providers/jdk.md#bouncycastle) or a
specific [OpenSSL linking option](providers/openssl3.md#linking-options)),
see [Choosing a Provider](providers/index.md).

For alternative ways to manage dependencies, such as [BOM](dependency-management.md#bom)
or [Gradle version catalog](dependency-management.md#gradle-version-catalog),
see [Dependency Management](dependency-management.md).

## Your first hash

```kotlin
// get a hasher
val hasher = CryptographyProvider.Default.get(SHA512).hasher()
// hash a message
val digest = hasher.hash("Kotlin is Awesome".encodeToByteArray())
```

Learn more about [Hashing](../primitives/operations/hashing.md).

## Sign a message

```kotlin
// get an algorithm
val ecdsa = CryptographyProvider.Default.get(ECDSA)
// generate a key pair
val keyPair = ecdsa.keyPairGenerator(EC.Curve.P256).generateKey()
// sign a message via private key
val signature = keyPair.privateKey
    .signatureGenerator(digest = SHA256)
    .generateSignature("message".encodeToByteArray())
// verify a signature via public key
val isValid = keyPair.publicKey
    .signatureVerifier(digest = SHA256)
    .tryVerifySignature("message".encodeToByteArray(), signature)
```

Learn more about [Digital Signatures](../primitives/operations/digital-signatures.md).

## Encrypt data

```kotlin
// get an algorithm
val aesGcm = CryptographyProvider.Default.get(AES.GCM)
// generate a key
val key = aesGcm.keyGenerator().generateKey()
// use cipher to encrypt and decrypt data
val cipher = key.cipher()
val ciphertext = cipher.encrypt(plaintext = "secretdata".encodeToByteArray())
val decrypted = cipher.decrypt(ciphertext = ciphertext)
```

Learn more about [AEAD](../primitives/operations/aead.md).

---

**Want to understand how these pieces connect?** See the [Primitives overview](../primitives/index.md).

