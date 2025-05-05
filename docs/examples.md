# Code examples

## SHA

An example shows how to get digest of some binary data.

```kotlin
// getting default provider
val provider = CryptographyProvider.Default
// getting SHA512 algorithm, which only provides hasher
//  types here and below are not required, and just needed to hint reader
val hasher: Hasher = provider.get(SHA512).hasher()
// now we can use hasher to create digest
val digest1: ByteArray = hasher.hash("text1".encodeToByteArray())
val digest2: ByteArray = hasher.hash("text1".encodeToByteArray())

// will print true
println(digest1.contentEquals(digest2))
```

## HMAC

An example shows how to generate, encode and decode keys as well as how to use them to generate and verify MAC signatures.

```kotlin
// getting default provider
val provider = CryptographyProvider.Default
// getting HMAC algorithm
val hmac = provider.get(HMAC)

// creating key generator with specified Digest algorithm
val keyGenerator = hmac.keyGenerator(SHA512)

// generating HMAC key
//  types here and below are not required, and just needed to hint reader
val key1: HMAC.Key = keyGenerator.generateKey()
// will generate different key
val key2: HMAC.Key = keyGenerator.generateKey()

// generating signature
val signature1: ByteArray = key1.signatureGenerator().generateSignature("text1".encodeToByteArray())
// using different key will provide different signature
val signature2: ByteArray = key2.signatureGenerator().generateSignature("text1".encodeToByteArray())

// will print false
println(signature1.contentEquals(signature2))

// we also, of course, can verify signature
val verificationResult: Boolean = key1.signatureVerifier().tryVerifySignature("text1".encodeToByteArray(), signature1)
// will print true
println(verificationResult)

// key also can be encoded and decoded
val encodedKey1: ByteArray = key1.encodeToByteArray(HMAC.Key.Format.RAW)
val decodedKey1: HMAC.Key = hmac.keyDecoder(SHA512).decodeFromByteArray(HMAC.Key.Format.RAW, encodedKey1)

val decodedKeyVerificationResult: Boolean = decodedKey1.signatureVerifier().tryVerifySignature("text1".encodeToByteArray(), signature1)
// will print true
println(decodedKeyVerificationResult)
```

## AES-GCM

An example shows how to generate, encode and decode keys as well as how to use them to encrypt or decrypt data

```kotlin
// getting default provider
val provider = CryptographyProvider.Default
// getting AES-GCM algorithm
val aesGcm = provider.get(AES.GCM)

// creating key generator with specified key size
val keyGenerator = aesGcm.keyGenerator(keySize =  Key.Size.B256)

// generating an AES key
//  types here and below are not required, and just needed to hint reader
val key: AES.GCM.Key = keyGenerator.generateKey()

// encrypting data
//  for simplicity of example, we will use default parameters
val cipher = key.cipher()
val ciphertext: ByteArray = cipher.encrypt(plaintext = "text1".encodeToByteArray())

// decrypting data, will print `text1`
println(cipher.decrypt(ciphertext = ciphertext).decodeToString())

// key also can be encoded and decoded
val encodedKey: ByteArray = key.encodeToByteArray(AES.Key.Format.RAW)
val decodedKey: AES.GCM.Key = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, encodedKey)

val decodedKeyCipher = decodedKey.cipher()
// decrypting data with the cipher with the same key, will print `text1`
println(decodedKeyCipher.decrypt(ciphertext = ciphertext).decodeToString())
```

## ECDSA

An example shows how to generate, encode and decode keys
as well as how to use them to generate and verify digital signatures using public key cryptography

```kotlin
// getting default provider
val provider = CryptographyProvider.Default
// getting ECDSA algorithm
val ecdsa = provider.get(ECDSA)

// creating key generator with the specified curve
val keyPairGenerator = ecdsa.keyPairGenerator(EC.Curve.P521)

// generating ECDSA key pair
//  types here and below are not required, and just needed to hint reader
val keyPair: ECDSA.KeyPair = keyPairGenerator.generateKey()

// generating signature using privateKey
val signature: ByteArray =
    keyPair.privateKey.signatureGenerator(digest = SHA512, format = ECDSA.SignatureFormat.DER)
        .generateSignature("text1".encodeToByteArray())

// verifying signature with publicKey, note, digest should be the same
val verificationResult: Boolean =
    keyPair.publicKey.signatureVerifier(digest = SHA512, format = ECDSA.SignatureFormat.DER)
        .tryVerifySignature("text1".encodeToByteArray(), signature)

// will print true
println(verificationResult)

// key also can be encoded and decoded
val encodedPublicKey: ByteArray = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.DER)
// note, the curve should be the same
val decodedPublicKey: ECDSA.PublicKey = ecdsa.publicKeyDecoder(EC.Curve.P521).decodeFromByteArray(EC.PublicKey.Format.DER, encodedPublicKey)

val decodedKeyVerificationResult: Boolean =
    decodedPublicKey.signatureVerifier(digest = SHA512, format = ECDSA.SignatureFormat.DER).tryVerifySignature("text1".encodeToByteArray(), signature)

// will print true
println(decodedKeyVerificationResult)
```
