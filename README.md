# cryptography-kotlin

A cryptography library for Kotlin Multiplatform, which wraps well-known future-proof platform-native solutions like
[OpenSSL](https://www.openssl.org),
[CryptoKit](https://developer.apple.com/documentation/cryptokit/),
[WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) or
[JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
with a type-safe uniform API, aligned defaults as well as tested for cross-compatibility between platforms.

## Quick start

Add dependencies:

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

Use the library:

```kotlin
// get a hasher
val sha = CryptographyProvider.Default.get(SHA512).hasher()
// hash a message
sha.hash("Kotlin is Awesome".encodeToByteArray())
```

For more, see the [Getting Started](https://whyoleg.github.io/cryptography-kotlin/getting-started/) guide
and [API Reference](https://whyoleg.github.io/cryptography-kotlin/api/).

## Supported algorithms

[//]: # (@formatter:off)
<!-- SUPPORTED_ALGORITHMS_START -->

| Operation | Algorithms |
|-----------|------------|
| [Hashing](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/hashing/) | SHA224, SHA256, SHA384, SHA512, SHA3, SHA1, MD5, RIPEMD160 |
| [MAC](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/mac/) | AES-CMAC, HMAC |
| [Digital Signatures](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/digital-signatures/) | RSA-PSS, RSA-PKCS1, ECDSA, EdDSA, DSA |
| [AEAD](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/aead/) | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| [Symmetric Encryption](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/symmetric-encryption/) | AES-CBC, AES-CTR, AES-ECB, AES-OFB, AES-CFB, AES-CFB8 |
| [Public-Key Encryption](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/public-key-encryption/) | RSA-OAEP, RSA-PKCS1, RSA-RAW |
| [Key Agreement](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/key-agreement/) | ECDH, XDH, DH |
| [Key Derivation](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/key-derivation/) | PBKDF2, HKDF |

<!-- SUPPORTED_ALGORITHMS_END -->
[//]: # (@formatter:on)

Detailed documentation is available on the [project website](https://whyoleg.github.io/cryptography-kotlin/),
including the full [provider support matrix](https://whyoleg.github.io/cryptography-kotlin/primitives/operations/).
