/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.EC.Curve.Companion.P256
import dev.whyoleg.cryptography.api.keys.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface HashOperation {
    public fun hash(data: ByteString): ByteString
    public fun hash(data: RawSource): ByteString
}

public interface AsyncHashOperation {
    public suspend fun hash(data: ByteString): ByteString
    public suspend fun hash(data: RawSource): ByteString
}

public interface SignOperation {
    public fun sign(data: ByteString): ByteString
    public fun sign(data: RawSource): ByteString
}

public interface AsyncSignOperation {
    public suspend fun sign(data: ByteString): ByteString
    public suspend fun sign(data: RawSource): ByteString
}

public interface VerifyOperation {
    public fun verify(data: ByteString, signature: ByteString)
    public fun verify(data: RawSource, signature: ByteString)

    public fun tryVerify(data: ByteString, signature: ByteString): Boolean
    public fun tryVerify(data: RawSource, signature: ByteString): Boolean
}

public interface AsyncVerifyOperation {
    public suspend fun verify(data: ByteString, signature: ByteString)
    public suspend fun verify(data: RawSource, signature: ByteString)

    public suspend fun tryVerify(data: ByteString, signature: ByteString): Boolean
    public suspend fun tryVerify(data: RawSource, signature: ByteString): Boolean
}

// algs

public interface HashAlgorithm : HashOperation {
    public val async: AsyncHashOperation
}

//public val SHA256: HashAlgorithm = TODO()

public object HMAC {
    public fun generateKey(size: Int): HmacRawKey = TODO()
    public fun decode(key: ByteString): HmacRawKey = TODO()

    public fun withDigest(digest: Digest): HmacDigestKeyFactory = TODO()
}

public interface HmacDigestKeyFactory {
    public val async: AsyncHmacDigestKeyFactory

    public fun generateKey(size: Int): HmacDigestKey = TODO()
    public fun decode(key: ByteString): HmacDigestKey = TODO()
}

public interface HmacKey {
    // encode to
}

public interface HmacRawKey {
    public fun withDigest(digest: Digest): HmacDigestKey
}

public interface HmacDigestKey : SignOperation, VerifyOperation


public interface DeriveSecretOperation<P> {
    public fun deriveSecret(input: ByteString, parameters: P): ByteString
}

public interface HashAlgorithm

public interface HashOperation2 {
    public fun supports(algorithm: HashAlgorithm)

    public fun hash(algorithm: HashAlgorithm, data: ByteString): ByteString = TODO()

    public companion object Default : HashOperation2 {}

    public interface Async {
        public fun supports(algorithm: HashAlgorithm)

        public suspend fun hash(algorithm: HashAlgorithm, data: ByteString): ByteString = TODO()

        public companion object Default : Async
    }
}

public interface EncryptParameters

public interface EncryptOperation {
    public fun supports(parameters: EncryptParameters)

    public fun encrypt(
        parameters: EncryptParameters,
        plaintext: ByteString,
    ): ByteString = TODO()

    public object Default : EncryptOperation {}
}

public interface AesParameters {
    public val mode: AesCipherMode
    public val key: ByteArray
}

public class RsaPssSignatureParameters(
    public val key: RsaKey,
    public val parameters: HashParameters,
    public val saltSize: BinarySize,
)

public class EcdsaSignature(
    public val format: String,
    public val value: ByteString,
)

public interface EncryptOperation2<P> {
    public fun encrypt(parameters: P, plaintext: ByteString): ByteString
}

public interface KeyGenerationOperation<P, K> {
    public fun generateKey(parameters: P): K
}

public object AES128 : KeyGenerationOperation<Unit, AesKey>

public sealed interface AesCipherParameters {
    public class Gcm(
        public val tagSize: BinarySize,
        public val iv: ByteString = ByteString(CryptographyRandom.nextBytes(12)),
        public val aad: ByteString? = null,
    ) : AesCipherParameters
}

public interface AesKey : EncryptOperation2<AesCipherParameters>

public interface RsaPublicKey {
    // params of key
}

public interface RsaPrivateKey {
    // params of key
}

private suspend fun prepareSecreteKey(myKey: String) {
    val key: RsaPublicKey = RsaPublicKey.decodePem(myKey)

    RsaKeyPair.generate(size)

    key.get(RsaPssParameters(SHA256, saltSize = 32))

    RsaPssSignature.verify(key, data, signature)



    Hpke.sender(
        key, // Ecdsa key
        params,
    )








    ECDH.deriveSharedSecret(
        localPrivateKey,
        remotePublicKey
    )
    Hpke()


    generateEcKey(curve = P256)

    key.encrypt(
        AesGcmParameters(),
        plaintext
    ): ciphertext


//    hash(SHA256, myKey.encodeToByteString())
    HashOperation2.hash(SHA256, myKey.encodeToByteString())
    HashOperation2.Async.hash(SHA256, myKey.encodeToByteString())


    val key = KeyGenerator.generateKey(AES128) // returns AesKey

    key


    SHA256.hash(myKey.encodeToByteString())
    SHA256.async.hash(myKey.encodeToByteString())

    SHA256.createHashFunction()

    SHA256

    Aes256

    HMAC
        .async.generateKey(123)
        .configureWith(SHA256)
        .async.sign(myKey.encodeToByteString())

    HMAC.configureWith(SHA256)
        .async.generateKey(size = 123)
        .async.sign(myKey.encodeToByteString())

    RSA.decodePem()

    RSA.generateKeyPair(...).publicKey

    AES.generateKey(AES)

    AES.decodeKey(
        SHA256.hash(myKey.encodeToByteArray()).copyOf(32)
    ).cipher(
        AesCipherMode.ECB(padding = true),
        AesCipherMode.ECB.NoPadding,
        AesCipherMode.ECB
    )

    rsaPublicKey
        .reinterpret(PSS(SHA256))
        .sign(myKey.encodeToByteArray())

    HKDF(
        SHA256,
        outputSize = 32,
        salt = myKey.encodeToByteArray(),
        info = "some info".encodeToByteArray()
    ).async.derive()

    AES128
        .generateKey()
        .configureWith(GCM())
        .encrypt()


    ECDSA.configureWith(P256)
        .generateKeyPair()
        .publicKey
        .verify(...)

    ECDSA(P256)
        .decodeRawPublicKey(key)
        .decodePublicKey(EcKeyFormat.RAW, key)
        .decodeDerPublicKey(key)
        .encodeToDer()
        .verify(data, signature)

    ECDH // = EC(Mode.ECDSA) // algo based
        .generateKeyPair()

    EC // key based


    RSA.using(PSS(SHA256))
    RSA.with(PSS(SHA256))

    rsaPublicKey.using(PSS(SHA256)) // JWK parsed
    rsaPublicKey.with(PSS(SHA256))


    RSA(PSS(SHA256))
//        .async
        .generateKeyPair()
        .publicKey
//        .async
        .sign(...)

    RSA
//        .async
        .generateKeyPair()
        .publicKey
        .withMode(PSS(SHA256))
        .reinterpret(PSS(SHA256))
//        .async
        .sign(...)
}

public sealed interface HashMode {}

public sealed interface RsaMode {
    public data class PSS(
        public val digest: Digest,
        public val saltSize: BinarySize = digest.size,
    ) : RsaMode

    public data class PKCS1v1_5(
        public val digest: Digest,
    ) : RsaMode

    public data class OAEP(
        public val digest: Digest,
        public val label: ByteString? = null,
    ) : RsaMode

    public object RAW : RsaMode
}

public sealed interface AesCipherMode {
    public open class ECB(public val padding: Boolean) : AesCipherMode {
        public companion object PKCS5Padding : ECB(true)
        public object NoPadding : ECB(false)
    }
}

//public val SHA256: Digest
