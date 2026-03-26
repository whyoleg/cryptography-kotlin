# Hybrid Encryption

This recipe follows the pattern used in
[CMS EnvelopedData (RFC 5652)](https://datatracker.ietf.org/doc/html/rfc5652) and
[HPKE (RFC 9180)](https://datatracker.ietf.org/doc/html/rfc9180).
Large data is encrypted with [AES-GCM](../operations/aead.md) using a random key,
then that key is encrypted with [RSA-OAEP](../operations/public-key-encryption.md).
The recipient decrypts the AES key with their RSA private key, then decrypts the data.

Encrypt data for a recipient:

```kotlin
val rsaOaep = provider.get(RSA.OAEP)
val recipientKeyPair = rsaOaep.keyPairGenerator(3072.bits).generateKey()

// --- Generate a random AES-GCM key and encrypt the data ---
val aesGcm = provider.get(AES.GCM)
val aesKey = aesGcm.keyGenerator().generateKey()
val ciphertext = aesKey.cipher().encrypt(plaintext = "Large payload...".encodeToByteArray())

// --- Encode the AES key to raw bytes, then encrypt it with RSA-OAEP ---
val aesKeyBytes = aesKey.encodeToByteArray(AES.Key.Format.RAW)
val encryptedKey = recipientKeyPair.publicKey.encryptor().encrypt(aesKeyBytes)

// Send: encryptedKey + ciphertext
```

The recipient decrypts the AES key with their RSA private key, then decrypts the data:

```kotlin
// --- Decrypt the AES key with the RSA private key ---
val decryptedKeyBytes = recipientKeyPair.privateKey.decryptor().decrypt(encryptedKey)

// --- Import the AES key and decrypt the data ---
val restoredKey = provider.get(AES.GCM)
    .keyDecoder()
    .decodeFromByteArray(AES.Key.Format.RAW, decryptedKeyBytes)
val plaintext = restoredKey.cipher().decrypt(ciphertext = ciphertext)
println(plaintext.decodeToString()) // "Large payload..."
```

RSA-OAEP can only encrypt data shorter than its key size
(roughly `keyBytes - 2 * hashBytes - 2`), so it is used to encrypt the small AES key
rather than the data itself.
