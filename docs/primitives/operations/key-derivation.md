# Key Derivation

Key derivation functions transform raw input material into well-formed cryptographic keys. This library provides two
algorithms for two fundamentally different scenarios:

- **HKDF** (KDF) -- derives keys from high-entropy input such as key agreement output or random bytes. Fast by design.
- **PBKDF2** (password-based) -- derives keys from low-entropy passwords. Deliberately slow to resist brute-force attacks.

!!! note "Assumed imports"

    All examples on this page assume the following imports and setup:

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*
    import dev.whyoleg.cryptography.random.*
    import dev.whyoleg.cryptography.BinarySize.Companion.bits

    val provider = CryptographyProvider.Default
    ```

## HKDF

HKDF (HMAC-based Key Derivation Function) derives keys from input material that already has sufficient entropy but is
not in the right format for direct use as a cryptographic key -- for example, the raw shared secret from an ECDH key
agreement. It is fast by design: a single HMAC pass to extract, then expand to the desired length.

See [Secure Messaging](../recipes/secure-messaging.md) for a complete example using HKDF with key agreement.

### Basic Usage

Get the algorithm, configure a [`SecretDerivation`][SecretDerivation] with digest, output size, salt, and info, then
[`deriveSecretToByteArray`][deriveSecret] from input key material:

```kotlin
val hkdf = provider.get(HKDF)

// Input key material -- e.g., a shared secret from ECDH
val inputKeyMaterial = ByteArray(32) // placeholder for actual key material

val salt = CryptographyRandom.nextBytes(32)

val derivation = hkdf.secretDerivation(
    digest = SHA256,
    outputSize = 256.bits,
    salt = salt,
    info = "encryption-key".encodeToByteArray()
)

val derivedKey: ByteArray = derivation.deriveSecretToByteArray(inputKeyMaterial)
```

The [`SecretDerivation`][SecretDerivation] instance is stateless and reusable. For the same input and parameters, the output is always
identical -- HKDF is deterministic.

### Deriving Multiple Keys

Use different `info` strings to derive independent keys from the same input material:

```kotlin
val hkdf = provider.get(HKDF)
val salt = CryptographyRandom.nextBytes(32)

// Derive an encryption key
val encryptionKey = hkdf.secretDerivation(
    digest = SHA256,
    outputSize = 256.bits,
    salt = salt,
    info = "encryption".encodeToByteArray()
).deriveSecretToByteArray(sharedSecret)

// Derive a separate MAC key from the same input
val macKey = hkdf.secretDerivation(
    digest = SHA256,
    outputSize = 256.bits,
    salt = salt,
    info = "authentication".encodeToByteArray()
).deriveSecretToByteArray(sharedSecret)
```

The two derived keys are cryptographically independent -- knowing one reveals nothing about the other. This pattern is
widely used in protocols like TLS 1.3.

## PBKDF2

PBKDF2 (Password-Based Key Derivation Function 2) derives keys from passwords -- short, human-chosen strings with far
less entropy than a random key. It iterates HMAC hundreds of thousands of times, making each guess expensive for an
attacker.

See [Password-Based Encryption](../recipes/password-based-encryption.md) for a complete example using PBKDF2 with
AES-GCM.

### Basic Usage

Get the algorithm, configure a [`SecretDerivation`][SecretDerivation] with digest, iteration count, output size, and salt,
then [`deriveSecretToByteArray`][deriveSecret] from the password bytes:

```kotlin
val pbkdf2 = provider.get(PBKDF2)

val password = "user-password".encodeToByteArray()
val salt = CryptographyRandom.nextBytes(16) // store alongside ciphertext

val derivation = pbkdf2.secretDerivation(
    digest = SHA256,
    iterations = 600_000,
    outputSize = 256.bits,
    salt = salt
)

val derivedKey: ByteArray = derivation.deriveSecretToByteArray(password)
```

The [`SecretDerivation`][SecretDerivation] instance is deterministic -- the same password, salt, iterations, digest, and output size always
produce the same output. This is essential for decryption: store the salt and parameters alongside the ciphertext so the
key can be reconstructed later.

### Iteration Count

The iteration count is the primary tuning parameter. A higher count means more work per derivation, which slows down
both the legitimate user and any attacker. The
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
recommends **600,000 iterations for SHA-256**.

## Supported Algorithms

--8<-- "operations/key-derivation.md"

[SecretDerivation]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-secret-derivation/index.html

[deriveSecret]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-secret-derivation/index.html
