# Key Agreement

Key agreement allows two parties to derive a shared secret over an insecure channel without ever transmitting
the secret itself. Each party combines their own private key with the other party's public key, and the
mathematics guarantees both sides arrive at the same shared secret independently.

!!! note "Assumed imports"

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*

    val provider = CryptographyProvider.Default
    ```

## Basic Usage

Both parties generate key pairs on the same curve, exchange public keys, and derive the same shared secret.

```kotlin
val ecdh = provider.get(ECDH)

// Step 1: Both parties generate key pairs on the same curve
val aliceKeyPair = ecdh.keyPairGenerator(EC.Curve.P256).generateKey()
val bobKeyPair = ecdh.keyPairGenerator(EC.Curve.P256).generateKey()

// Step 2: They exchange public keys (over the network, via a server, etc.)
val alicePublicKey = aliceKeyPair.publicKey
val bobPublicKey = bobKeyPair.publicKey

// Step 3: Each party derives the shared secret independently
val aliceSharedSecret = aliceKeyPair.privateKey
    .sharedSecretGenerator()
    .generateSharedSecretToByteArray(bobPublicKey)

val bobSharedSecret = bobKeyPair.privateKey
    .sharedSecretGenerator()
    .generateSharedSecretToByteArray(alicePublicKey)

// Step 4: Both shared secrets are identical
println(aliceSharedSecret.contentEquals(bobSharedSecret)) // true
```

The derivation is symmetric -- it does not matter which side contributes the private key and which
contributes the public key. The result is the same either way.

The [`sharedSecretGenerator`][SharedSecretGenerator] returns a reusable object --
you can derive shared secrets with multiple peers without re-creating it.

!!! warning "Do not use the raw shared secret as an encryption key"

    The raw output of key agreement has mathematical structure that could weaken a cipher.
    Always pass the shared secret through a key derivation function like HKDF before using it
    for encryption or authentication.

    A typical pipeline:

    1. **Key agreement** -- derive the raw shared secret (this page)
    2. **Key derivation** -- feed it into HKDF to produce a proper key (see [Key Derivation](key-derivation.md))
    3. **Encryption** -- use the derived key with AES-GCM or another cipher (see [AEAD](aead.md))

    See [Secure Messaging](../recipes/secure-messaging.md) for a complete end-to-end example.

## Supported Algorithms

--8<-- "operations/key-agreement.md"

[SharedSecretGenerator]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-shared-secret-generator/index.html

[generateSharedSecret]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-shared-secret-generator/index.html

[generateKey]: ../../api/cryptography-core/dev.whyoleg.cryptography.operations/-key-generator/generate-key.html
