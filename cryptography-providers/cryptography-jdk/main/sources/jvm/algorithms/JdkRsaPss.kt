package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import java.math.*
import java.security.spec.*

internal class JdkRsaPss(
    private val state: JdkCryptographyState,
) : RSA.PSS {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PSS.PublicKey> =
        RsaPssPublicKeyDecoder(state, digest.hashAlgorithmName())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        RsaPssPrivateKeyDecoder(state, digest.hashAlgorithmName())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.PSS.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.bits,
            when (publicExponent) {
                RSA.PublicExponent.F4        -> RSAKeyGenParameterSpec.F4
                is RSA.PublicExponent.Bytes  -> BigInteger(publicExponent.value)
                is RSA.PublicExponent.Number -> publicExponent.value.toBigInteger()
                is RSA.PublicExponent.Text   -> BigInteger(publicExponent.value)
            }
        )
        return RsaPssKeyPairGenerator(state, rsaParameters, digest.hashAlgorithmName())
    }
}


private class RsaPssPublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : JdkRsaPublicKeyDecoder<RSA.PSS.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.PSS.PublicKey = RsaPssPublicKey(state, this, hashAlgorithmName)
}

private class RsaPssPrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : JdkRsaPrivateKeyDecoder<RSA.PSS.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.PSS.PrivateKey = RsaPssPrivateKey(state, this, hashAlgorithmName)
}


private class RsaPssKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.PSS.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.PSS.KeyPair = RsaPssKeyPair(state, this, hashAlgorithmName)
}

private class RsaPssKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.PSS.KeyPair {
    override val publicKey: RSA.PSS.PublicKey = RsaPssPublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.PSS.PrivateKey = RsaPssPrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaPssPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : RSA.PSS.PublicKey {
    override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier {
        val parameters = PSSParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec.SHA1,
            saltLength.bytes,
            PSSParameterSpec.TRAILER_FIELD_BC
        )
        return RsaPssSignatureVerifier(state, key, parameters)
    }

    override fun encodeToBlocking(format: RSA.PublicKey.Format): Buffer = when (format) {
        RSA.PublicKey.Format.DER -> key.encoded
        RSA.PublicKey.Format.JWK -> TODO()
        RSA.PublicKey.Format.PEM -> TODO()
    }

    override suspend fun encodeTo(format: RSA.PublicKey.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private class RsaPssPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : RSA.PSS.PrivateKey {
    override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator {
        val parameters = PSSParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec.SHA1,
            saltLength.bytes,
            PSSParameterSpec.TRAILER_FIELD_BC
        )
        return RsaPssSignatureGenerator(state, key, parameters)
    }

    override fun encodeToBlocking(format: RSA.PrivateKey.Format): Buffer = when (format) {
        RSA.PrivateKey.Format.DER -> key.encoded
        RSA.PrivateKey.Format.JWK -> TODO()
        RSA.PrivateKey.Format.PEM -> TODO()
    }

    override suspend fun encodeTo(format: RSA.PrivateKey.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private class RsaPssSignatureGenerator(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val parameters: PSSParameterSpec,
) : SignatureGenerator {
    private val signature = state.signature("RSASSA-PSS")

    override val signatureSize: Int get() = TODO()

    override fun generateSignatureBlocking(dataInput: Buffer): Buffer = signature.use { signature ->
        signature.initSign(key, state.secureRandom)
        signature.setParameter(parameters)
        signature.update(dataInput)
        signature.sign()
    }

    override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return state.execute { generateSignatureBlocking(dataInput) }
    }
}

private class RsaPssSignatureVerifier(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val parameters: PSSParameterSpec,
) : SignatureVerifier {
    private val signature = state.signature("RSASSA-PSS")

    override val signatureSize: Int get() = TODO()
    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean = signature.use { signature ->
        signature.initVerify(key)
        signature.setParameter(parameters)
        signature.update(dataInput)
        signature.verify(signatureInput)
    }

    override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return state.execute { verifySignatureBlocking(dataInput, signatureInput) }
    }
}
