# Working with Keys

Keys are created by algorithms and used for operations. This page covers generation, encoding and
decoding, standard key formats, and accessing public keys from private keys.

!!! note "Assumed imports"

    All examples assume the following:

    ```kotlin
    import dev.whyoleg.cryptography.*
    import dev.whyoleg.cryptography.algorithms.*
    import dev.whyoleg.cryptography.BinarySize.Companion.bits

    val provider = CryptographyProvider.Default
    ```

## Generation

### Symmetric Keys

Symmetric algorithms produce a single shared key:

```kotlin
val aesGcm = provider.get(AES.GCM)
val key = aesGcm.keyGenerator().generateKey()
```

Some algorithms accept an optional key size parameter:

```kotlin
val key = aesGcm.keyGenerator(AES.Key.Size.B256).generateKey()
```

### Asymmetric Key Pairs

Asymmetric algorithms produce a key pair containing a public key and a private key.
EC algorithms require a curve, RSA algorithms accept a key size:

```kotlin
val ecdsa = provider.get(ECDSA)
val ecKeyPair = ecdsa.keyPairGenerator(EC.Curve.P256).generateKey()

val rsa = provider.get(RSA.OAEP)
val rsaKeyPair = rsa.keyPairGenerator(4096.bits).generateKey()
```

Generators are reusable -- call [`generateKey()`][generateKey] multiple times on the same generator to produce
independent keys without re-specifying parameters.

## Key Formats

| Format  | Encoding      | Description                                                                   |
|---------|---------------|-------------------------------------------------------------------------------|
| **RAW** | Binary        | Raw key bytes, no metadata, minimal overhead [^1]                             |
| **DER** | Binary        | ASN.1 binary (PKIX/SPKI for public, PKCS#8 for private) [^2]                  |
| **PEM** | Text (Base64) | Base64-wrapped DER with `BEGIN`/`END` headers [^2]                            |
| **JWK** | JSON          | JSON Web Key ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) [^3] |

[^1]:
**Apple (CommonCrypto)**: EC PrivateKey RAW encoding is supported, but decoding is not.
EC PublicKey RAW.Compressed is not supported.

[^2]:
**Apple (CommonCrypto)**: EC PrivateKey decoding requires the `publicKey` field
to be present in the `EcPrivateKey` structure per [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
Not all implementations include this optional field.
**JDK / WebCrypto**: EdDSA/XDH PrivateKey decoding may fail for formats that contain an embedded public key.

[^3]:
**JDK**: EC/EdDSA/XDH PrivateKey JWK format is only supported if the public key is available
(i.e., the key pair was generated via the library, decoded from a format containing the
public key, or [BouncyCastle](../getting-started/providers/jdk.md#bouncycastle) is on the classpath).

## Encoding

All keys implement [`Encodable`][Encodable]. Call [`encodeToByteArray(format)`][encodeToByteArray] to get a `ByteArray`,
or `encodeToByteString(format)` to get a [`ByteString`][ByteString]. For text formats (PEM, JWK), the
bytes are UTF-8 encoded text.

### Symmetric

```kotlin
val key = provider.get(AES.GCM).keyGenerator().generateKey()
val raw = key.encodeToByteArray(AES.Key.Format.RAW)
val jwk = key.encodeToByteArray(AES.Key.Format.JWK)
```

### Asymmetric

Public and private keys are encoded separately:

```kotlin
val ecdsa = provider.get(ECDSA)
val keyPair = ecdsa.keyPairGenerator(EC.Curve.P256).generateKey()

val publicDer = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.DER)
val privateDer = keyPair.privateKey.encodeToByteArray(EC.PrivateKey.Format.DER)
```

## Decoding

Decoding reconstructs a key object from encoded bytes. Each algorithm provides decoder methods
that return a [`Decoder`][Decoder] instance.

### Symmetric

```kotlin
val aesGcm = provider.get(AES.GCM)
val key = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, bytes)
```

### Asymmetric

Public and private keys have separate decoders. Decoders may require algorithm-specific parameters
(curve for EC, digest for HMAC, etc.):

```kotlin
val ecdsa = provider.get(ECDSA)

val publicKey = ecdsa.publicKeyDecoder(EC.Curve.P256)
    .decodeFromByteArray(EC.PublicKey.Format.DER, publicKeyBytes)

val privateKey = ecdsa.privateKeyDecoder(EC.Curve.P256)
    .decodeFromByteArray(EC.PrivateKey.Format.DER, privateKeyBytes)
```

Use [`decodeFromByteString(format, byteString)`][Decoder] when working with [`ByteString`][ByteString] instead of
`ByteArray`.

## Accessing Public Key from Private Key

For asymmetric algorithms, the public key can be retrieved from a private key:

```kotlin
val privateKey: ECDSA.PrivateKey = keyPair.privateKey
val publicKey: ECDSA.PublicKey = privateKey.publicKey
```

This is useful when you have only the private key (e.g., loaded from storage) and need the
corresponding public key for verification or sharing.

!!! warning "JDK provider limitation"

    On the JDK provider, `privateKey.publicKey` may throw an exception unless the key pair was
    generated via the library, the private key was decoded from a format containing the public
    key, or [BouncyCastle](../getting-started/providers/jdk.md#bouncycastle) is on the classpath.
    Other providers (CryptoKit, WebCrypto, OpenSSL3) support this without restrictions.

[Encodable]: ../api/cryptography-core/dev.whyoleg.cryptography.materials/-encodable/index.html

[encodeToByteArray]: ../api/cryptography-core/dev.whyoleg.cryptography.materials/-encodable/index.html

[Decoder]: ../api/cryptography-core/dev.whyoleg.cryptography.materials/-decoder/index.html

[generateKey]: ../api/cryptography-core/dev.whyoleg.cryptography.operations/-key-generator/generate-key.html

[ByteString]: https://kotlinlang.org/api/kotlinx-io/kotlinx-io-bytestring/kotlinx.io.bytestring/-byte-string/
