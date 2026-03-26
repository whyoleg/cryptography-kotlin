# Primitives

## Architecture

cryptography-kotlin is built around four concepts that connect in a chain:

**Provider --> Algorithm --> Key --> Operation**

1. A **Provider** wraps a platform-native cryptography implementation (OpenSSL, CryptoKit, WebCrypto, JCA)
2. From a provider, you get an **Algorithm** (like `AES.GCM` or `ECDSA`)
3. An algorithm gives you **Keys** -- via generation or decoding from an existing format
4. Keys give you **Operations** -- ciphers, hashers, signature generators, etc.

```kotlin
// 1. Get the algorithm from a provider
val aesGcm = CryptographyProvider.Default.get(AES.GCM)
// 2. Generate a key
val key = aesGcm.keyGenerator().generateKey()
// 3. Use the key for operations
val ciphertext = key.cipher().encrypt(plaintext)
```

For details on choosing and configuring providers, see [Choosing a Provider](../getting-started/providers/index.md).

## Working with Keys

Keys are created by algorithms and used for operations.
See [Working with Keys](keys.md) for generation, encoding/decoding, key formats, and accessing public keys from private keys.

## Operations

Each operation type has its own page with step-by-step examples:

- [Hashing](operations/hashing.md) -- compute digests of data
- [MAC](operations/mac.md) -- message authentication codes
- [AEAD](operations/aead.md) -- authenticated encryption with associated data
- [Symmetric Encryption](operations/symmetric-encryption.md) -- encrypt/decrypt with a shared key
- [Public-Key Encryption](operations/public-key-encryption.md) -- encrypt with public key, decrypt with private
- [Digital Signatures](operations/digital-signatures.md) -- signing and verification
- [Key Agreement](operations/key-agreement.md) -- derive shared secrets
- [Key Derivation](operations/key-derivation.md) -- derive keys from passwords or key material

For a complete algorithm/provider support matrix, see the [Operations index](operations/index.md).

## Recipes

End-to-end examples showing how to combine algorithms for real-world tasks:

- [Secure Messaging](recipes/secure-messaging.md) -- ECDH + HKDF + AES-GCM
- [Password-Based Encryption](recipes/password-based-encryption.md) -- PBKDF2 + AES-GCM
- [Hybrid Encryption](recipes/hybrid-encryption.md) -- RSA-OAEP + AES-GCM
