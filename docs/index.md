---
hide:
  - navigation
---

# cryptography-kotlin

A cryptography library for Kotlin Multiplatform, which wraps well-known future-proof platform-native solutions like
[OpenSSL](https://www.openssl.org),
[CryptoKit](https://developer.apple.com/documentation/cryptokit/),
[WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) or
[JCA](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
with a type-safe uniform API, aligned defaults as well as tested for cross-compatibility between platforms.

```kotlin
// get a hasher
val sha = CryptographyProvider.Default.get(SHA512).hasher()
// hash a message
sha.hash("Kotlin is Awesome".encodeToByteArray())
```

- **New here?** Check out the [Getting Started](getting-started/index.md) guide
- **Need the API docs?** See the [API Reference](api/index.html)

## Standalone modules

The following modules can be used independently of the main cryptography API,
without pulling in any providers or algorithm definitions.

| Module                                  | Description                                              |
|-----------------------------------------|----------------------------------------------------------|
| [cryptography-random][random]           | Platform-dependent CSPRNG via kotlin `Random` API        |
| [cryptography-bigint][bigint]           | Arbitrary-precision integer for multiplatform            |
| [cryptography-serialization-pem][pem]   | PEM encoding/decoding (RFC 7468)                         |
| [cryptography-serialization-asn1][asn1] | ASN.1/DER binary serialization via kotlinx.serialization |

[random]: api/cryptography-random/index.html

[bigint]: api/cryptography-bigint/index.html

[pem]: api/cryptography-serialization-pem/index.html

[asn1]: api/cryptography-serialization-asn1/index.html
