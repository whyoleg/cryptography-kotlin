# Secure Messaging

This recipe follows the key exchange pattern used in
[HPKE (RFC 9180)](https://datatracker.ietf.org/doc/html/rfc9180) and similar
protocols like Signal and TLS 1.3. Two parties establish a shared secret via
[ECDH](../operations/key-agreement.md), derive an encryption key with
[HKDF](../operations/key-derivation.md), then communicate using
[AES-GCM](../operations/aead.md).

Alice sends an encrypted message to Bob:

```kotlin
// --- Both parties generate ECDH key pairs and exchange public keys ---
val ecdh = provider.get(ECDH)
val aliceKeyPair = ecdh.keyPairGenerator(EC.Curve.P256).generateKey()
val bobKeyPair = ecdh.keyPairGenerator(EC.Curve.P256).generateKey()

// --- Alice: compute shared secret using her private key and Bob's public key ---
val aliceSharedSecret = aliceKeyPair.privateKey
    .sharedSecretGenerator()
    .generateSharedSecretToByteArray(bobKeyPair.publicKey)

// --- Alice: derive an AES-256 key from the shared secret via HKDF ---
val hkdf = provider.get(HKDF)
val salt = ByteArray(32) // in practice, use a random or agreed-upon salt
val derivedKeyBytes = hkdf.secretDerivation(
    digest = SHA256,
    outputSize = 256.bits,
    salt = salt,
    info = "messaging-key".encodeToByteArray()
).deriveSecretToByteArray(aliceSharedSecret)

// --- Alice: import the derived bytes as an AES-GCM key and encrypt ---
val aesGcm = provider.get(AES.GCM)
val encryptionKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, derivedKeyBytes)
val ciphertext = encryptionKey.cipher().encrypt(plaintext = "Hello, Bob!".encodeToByteArray())
```

Bob derives the same shared secret and key, then decrypts:

```kotlin
// --- Bob: same shared secret via his private key + Alice's public key ---
val bobSharedSecret = bobKeyPair.privateKey
    .sharedSecretGenerator()
    .generateSharedSecretToByteArray(aliceKeyPair.publicKey)

// --- Bob: same HKDF parameters produce the same key ---
val bobDerivedKeyBytes = provider.get(HKDF).secretDerivation(
    digest = SHA256,
    outputSize = 256.bits,
    salt = salt,
    info = "messaging-key".encodeToByteArray()
).deriveSecretToByteArray(bobSharedSecret)

// --- Bob: decrypt ---
val decryptionKey = provider.get(AES.GCM)
    .keyDecoder()
    .decodeFromByteArray(AES.Key.Format.RAW, bobDerivedKeyBytes)
val plaintext = decryptionKey.cipher().decrypt(ciphertext = ciphertext)
println(plaintext.decodeToString()) // "Hello, Bob!"
```

The raw ECDH shared secret should never be used directly as an encryption key.
Always pass it through a key derivation function like HKDF first.
