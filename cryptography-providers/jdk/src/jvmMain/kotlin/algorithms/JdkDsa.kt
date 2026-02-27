/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.unwrapPem
import dev.whyoleg.cryptography.providers.base.materials.wrapPem
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.base.checkBounds
import java.math.BigInteger
import java.security.interfaces.*
import java.security.spec.*

internal class JdkDsa(
    private val state: JdkCryptographyState,
) : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder()

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder()

    override fun keyPairGenerator(keySize: BinarySize): KeyGenerator<DSA.KeyPair> = DsaKeyPairGenerator(keySize)

    private inner class DsaPublicKeyDecoder :
        JdkPublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>(state, "DSA") {

        override fun decodeFromByteArrayBlocking(format: DSA.PublicKey.Format, bytes: ByteArray): DSA.PublicKey = decodeFromDer(
            when (format) {
                DSA.PublicKey.Format.JWK -> error("$format is not supported")
                DSA.PublicKey.Format.DER -> bytes
                DSA.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, bytes)
            }
        )

        override fun JPublicKey.convert(): DSA.PublicKey = DsaPublicKey(this)
    }

    private inner class DsaPrivateKeyDecoder :
        JdkPrivateKeyDecoder<DSA.PrivateKey.Format, DSA.PrivateKey>(state, "DSA") {

        override fun decodeFromByteArrayBlocking(format: DSA.PrivateKey.Format, bytes: ByteArray): DSA.PrivateKey = decodeFromDer(
            when (format) {
                DSA.PrivateKey.Format.JWK -> error("$format is not supported")
                DSA.PrivateKey.Format.DER -> bytes
                DSA.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, bytes)
            }
        )

        override fun JPrivateKey.convert(): DSA.PrivateKey = DsaPrivateKey(this, publicKey = null)
    }

    private inner class DsaKeyPairGenerator(
        private val keySize: BinarySize,
    ) : JdkKeyPairGenerator<DSA.KeyPair>(state, "DSA") {

        override fun JKeyPairGenerator.init() {
            initialize(keySize.inBits, state.secureRandom)
        }

        override fun JKeyPair.convert(): DSA.KeyPair {
            val publicKey = DsaPublicKey(public)
            val privateKey = DsaPrivateKey(private, publicKey)
            return DsaKeyPair(publicKey, privateKey)
        }
    }

    private class DsaKeyPair(
        override val publicKey: DSA.PublicKey,
        override val privateKey: DSA.PrivateKey,
    ) : DSA.KeyPair

    private inner class DsaPublicKey(
        private val key: JPublicKey,
    ) : DSA.PublicKey, JdkEncodableKey<DSA.PublicKey.Format>(key) {

        override fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>?,
            format: DSA.SignatureFormat,
        ): SignatureVerifier {
            val algorithm = digest.dsaSignatureAlgorithmName()
            val verifier = JdkSignatureVerifier(state, key, algorithm, null)

            return when (format) {
                DSA.SignatureFormat.DER -> verifier
                DSA.SignatureFormat.RAW -> DsaRawSignatureVerifier(
                    derVerifier = verifier,
                    qSize = (key as DSAPublicKey).params.q.byteSize()
                )
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PublicKey.Format): ByteArray = when (format) {
            DSA.PublicKey.Format.JWK -> error("$format is not supported")
            DSA.PublicKey.Format.DER -> encodeToDer()
            DSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class DsaPrivateKey(
        private val key: JPrivateKey,
        private var publicKey: DSA.PublicKey?,
    ) : DSA.PrivateKey, JdkEncodableKey<DSA.PrivateKey.Format>(key) {

        override fun getPublicKeyBlocking(): DSA.PublicKey {
            if (publicKey == null) {
                publicKey = derivePublicKeyFromPrivate(key)
            }
            return publicKey!!
        }

        override fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>?,
            format: DSA.SignatureFormat,
        ): SignatureGenerator {
            val algorithm = digest.dsaSignatureAlgorithmName()
            val generator = JdkSignatureGenerator(state, key, algorithm, null)

            return when (format) {
                DSA.SignatureFormat.DER -> generator
                DSA.SignatureFormat.RAW -> DsaRawSignatureGenerator(
                    derGenerator = generator,
                    qSize = (key as DSAPrivateKey).params.q.byteSize()
                )
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PrivateKey.Format): ByteArray = when (format) {
            DSA.PrivateKey.Format.JWK -> error("$format is not supported")
            DSA.PrivateKey.Format.DER -> encodeToDer()
            DSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }

    private fun derivePublicKeyFromPrivate(privateKey: JPrivateKey): DSA.PublicKey {
        val dsaPrivateKey = privateKey as? DSAPrivateKey
            ?: error("Expected DSAPrivateKey, got: ${privateKey::class.qualifiedName}")

        val params = dsaPrivateKey.params
        val p = params.p
        val g = params.g
        val x = dsaPrivateKey.x

        val y: BigInteger = g.modPow(x, p)

        val spec = DSAPublicKeySpec(y, params.p, params.q, params.g)
        val factory = state.keyFactory("DSA")
        val jPublic = factory.use { it.generatePublic(spec) } as JPublicKey
        return DsaPublicKey(jPublic)
    }
}

private fun CryptographyAlgorithmId<Digest>?.dsaSignatureAlgorithmName(): String = when (this) {
    null -> "NONEwithDSA"
    SHA1 -> "SHA1withDSA"
    SHA224 -> "SHA224withDSA"
    SHA256 -> "SHA256withDSA"
    SHA384 -> "SHA384withDSA"
    SHA512 -> "SHA512withDSA"
    else -> throw IllegalStateException("Unsupported hash algorithm for DSA: $this")
}

private class DsaRawSignatureGenerator(
    private val derGenerator: SignatureGenerator,
    private val qSize: Int,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = RawSignFunction(derGenerator.createSignFunction(), qSize)

    private class RawSignFunction(
        private val derSignFunction: SignFunction,
        private val qSize: Int,
    ) : SignFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derSignFunction.update(source, startIndex, endIndex)
        }

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val signature = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
            signature.copyInto(destination, destinationOffset)
            return signature.size
        }

        override fun signToByteArray(): ByteArray {
            val derSignature = derSignFunction.signToByteArray()

            val signatureValue = Der.decodeFromByteArray(DsaSignatureValue.serializer(), derSignature)

            val r = signatureValue.r.encodeToByteArray().trimLeadingZeros()
            val s = signatureValue.s.encodeToByteArray().trimLeadingZeros()

            val rawSignature = ByteArray(qSize * 2)
            r.copyInto(rawSignature, qSize - r.size)
            s.copyInto(rawSignature, qSize * 2 - s.size)
            return rawSignature
        }

        override fun reset() = derSignFunction.reset()
        override fun close() = derSignFunction.close()
    }
}

private class DsaRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val qSize: Int,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = RawVerifyFunction(derVerifier.createVerifyFunction(), qSize)

    private class RawVerifyFunction(
        private val derVerifyFunction: VerifyFunction,
        private val qSize: Int,
    ) : VerifyFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derVerifyFunction.update(source, startIndex, endIndex)
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            check((endIndex - startIndex) == qSize * 2) {
                "Expected signature size ${qSize * 2}, received: ${endIndex - startIndex}"
            }

            val r = signature.copyOfRange(startIndex, startIndex + qSize).makePositive()
            val s = signature.copyOfRange(startIndex + qSize, endIndex).makePositive()

            val signatureValue = DsaSignatureValue(
                r = r.decodeToBigInt(),
                s = s.decodeToBigInt()
            )
            val derSignature = Der.encodeToByteArray(DsaSignatureValue.serializer(), signatureValue)

            return derVerifyFunction.tryVerify(derSignature)
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun reset() = derVerifyFunction.reset()
        override fun close() = derVerifyFunction.close()
    }
}

private fun BigInteger.byteSize(): Int = (bitLength() + 7) / 8
private fun ByteArray.makePositive(): ByteArray = if (this[0] < 0) byteArrayOf(0, *this) else this
private fun ByteArray.trimLeadingZeros(): ByteArray {
    var i = 0
    while (i < size && this[i] == 0.toByte()) i++
    return if (i == 0) this else copyOfRange(i, size)
}
