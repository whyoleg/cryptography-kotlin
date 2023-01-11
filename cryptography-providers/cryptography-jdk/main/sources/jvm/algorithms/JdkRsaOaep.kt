package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import java.math.*
import java.security.spec.*
import javax.crypto.spec.*

internal class JdkRsaOaep(
    private val state: JdkCryptographyState,
) : RSA.OAEP {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> =
        RsaOaepPublicKeyDecoder(state, digest.hashAlgorithmName())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        RsaOaepPrivateKeyDecoder(state, digest.hashAlgorithmName())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.OAEP.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.bits,
            when (publicExponent) {
                RSA.PublicExponent.F4        -> RSAKeyGenParameterSpec.F4
                is RSA.PublicExponent.Bytes  -> BigInteger(publicExponent.value)
                is RSA.PublicExponent.Number -> publicExponent.value.toBigInteger()
                is RSA.PublicExponent.Text   -> BigInteger(publicExponent.value)
            }
        )
        return RsaOaepKeyPairGenerator(state, rsaParameters, digest.hashAlgorithmName())
    }
}

private class RsaOaepPublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : JdkPublicKeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey>(state, "RSA") {
    override fun JPublicKey.convert(): RSA.OAEP.PublicKey {
        return RsaOaepPublicKey(state, this, hashAlgorithmName)
    }
}

private class RsaOaepPrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : JdkPrivateKeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey>(state, "RSA") {
    override fun JPrivateKey.convert(): RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.OAEP.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.OAEP.KeyPair = RsaOaepKeyPair(state, this, hashAlgorithmName)
}

private class RsaOaepKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.OAEP.KeyPair {
    override val publicKey: RSA.OAEP.PublicKey = RsaOaepPublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.OAEP.PrivateKey = RsaOaepPrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaOaepPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PublicKey {
    private val encryptor = RsaOaepEncryptor(state, key, hashAlgorithmName)
    override fun encryptor(): AuthenticatedEncryptor = encryptor
    override fun encodeToBlocking(format: RSA.PublicKey.Format): Buffer = when (format) {
        RSA.PublicKey.Format.DER -> key.encoded
        RSA.PublicKey.Format.JWK -> TODO()
        RSA.PublicKey.Format.PEM -> TODO()
    }

    override suspend fun encodeTo(format: RSA.PublicKey.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private class RsaOaepPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    hashAlgorithmName: String,
) : RSA.OAEP.PrivateKey {
    private val decryptor = RsaOaepDecryptor(state, key, hashAlgorithmName)
    override fun decryptor(): AuthenticatedDecryptor = decryptor

    override fun encodeToBlocking(format: RSA.PrivateKey.Format): Buffer = when (format) {
        RSA.PrivateKey.Format.DER -> key.encoded
        RSA.PrivateKey.Format.JWK -> TODO()
        RSA.PrivateKey.Format.PEM -> TODO()
    }

    override suspend fun encodeTo(format: RSA.PrivateKey.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private class RsaOaepEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : AuthenticatedEncryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun ciphertextSize(plaintextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(plaintextInput: Buffer, associatedData: Buffer?): Buffer = cipher.use { cipher ->
        val parameters = OAEPParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec.SHA1,
            associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
        )
        cipher.init(JCipher.ENCRYPT_MODE, key, parameters, state.secureRandom)
        cipher.doFinal(plaintextInput)
    }

    override suspend fun encrypt(plaintextInput: Buffer, associatedData: Buffer?): Buffer {
        return state.execute { encryptBlocking(plaintextInput, associatedData) }
    }
}

private class RsaOaepDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : AuthenticatedDecryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")
    override fun plaintextSize(ciphertextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(ciphertextInput: Buffer, associatedData: Buffer?): Buffer = cipher.use { cipher ->
        val parameters = OAEPParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec.SHA1,
            associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
        )
        cipher.init(JCipher.DECRYPT_MODE, key, parameters, state.secureRandom)
        cipher.doFinal(ciphertextInput)
    }

    override suspend fun decrypt(ciphertextInput: Buffer, associatedData: Buffer?): Buffer {
        return state.execute { decryptBlocking(ciphertextInput, associatedData) }
    }
}
