# Password-Based Encryption

This recipe follows [PKCS#5 / RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018).
A key is derived from a password using [PBKDF2](../operations/key-derivation.md#pbkdf2),
then used to encrypt data with [AES-GCM](../operations/aead.md).
The salt is stored alongside the ciphertext so the same key can be reconstructed for
decryption.

Encrypt data with a password:

```kotlin
val password = "correct-horse-battery-staple".encodeToByteArray()
val salt = CryptographyRandom.nextBytes(16)

// --- Derive a 256-bit key from the password ---
val derivedKeyBytes = provider.get(PBKDF2).secretDerivation(
    digest = SHA256,
    iterations = 600_000,
    outputSize = 256.bits,
    salt = salt
).deriveSecretToByteArray(password)

// --- Import the derived bytes as an AES-GCM key and encrypt ---
val aesGcm = provider.get(AES.GCM)
val aesKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, derivedKeyBytes)
val ciphertext = aesKey.cipher().encrypt(plaintext = "Secret data".encodeToByteArray())

// Store: salt + ciphertext (iteration count and digest are application constants)
```

Decrypt by re-deriving the key from the same password and stored salt:

```kotlin
// --- Retrieve the stored salt and ciphertext ---
val storedSalt: ByteArray = salt
val storedCiphertext: ByteArray = ciphertext

// --- Re-derive the key with the same parameters ---
val restoredKeyBytes = provider.get(PBKDF2).secretDerivation(
    digest = SHA256,
    iterations = 600_000,
    outputSize = 256.bits,
    salt = storedSalt
).deriveSecretToByteArray(password)

// --- Decrypt ---
val decryptionKey = provider.get(AES.GCM)
    .keyDecoder()
    .decodeFromByteArray(AES.Key.Format.RAW, restoredKeyBytes)
val plaintext = decryptionKey.cipher().decrypt(ciphertext = storedCiphertext)
println(plaintext.decodeToString()) // "Secret data"
```

The salt is not secret, but it must be stored alongside the ciphertext -- without the
exact same salt, the derived key will be different and decryption will fail.
See [Key Derivation](../operations/key-derivation.md) for guidance on choosing the
iteration count and digest.
