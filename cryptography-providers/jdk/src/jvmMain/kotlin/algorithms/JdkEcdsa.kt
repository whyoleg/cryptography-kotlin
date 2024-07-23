/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import java.security.interfaces.*

internal class JdkEcdsa(state: JdkCryptographyState) : JdkEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(state), ECDSA {
    override fun JPublicKey.convert(): ECDSA.PublicKey = EcdsaPublicKey(state, this)
    override fun JPrivateKey.convert(): ECDSA.PrivateKey = EcdsaPrivateKey(state, this)
    override fun JKeyPair.convert(): ECDSA.KeyPair = EcdsaKeyPair(public.convert(), private.convert())

    private class EcdsaKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcdsaPublicKey(
        private val state: JdkCryptographyState,
        private val key: JPublicKey,
    ) : ECDSA.PublicKey, BaseEcPublicKey(key) {
        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            val verifier = JdkSignatureVerifier(state, key, digest.hashAlgorithmName() + "withECDSA", null)
            return when (format) {
                ECDSA.SignatureFormat.DER -> verifier
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(verifier, (key as ECKey).params.curveOrderSize())
            }
        }
    }

    private class EcdsaPrivateKey(
        private val state: JdkCryptographyState,
        private val key: JPrivateKey,
    ) : ECDSA.PrivateKey, BaseEcPrivateKey(key) {
        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            val generator = JdkSignatureGenerator(state, key, digest.hashAlgorithmName() + "withECDSA", null)
            return when (format) {
                ECDSA.SignatureFormat.DER -> generator
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(generator, (key as ECKey).params.curveOrderSize())
            }
        }
    }
}

private class EcdsaRawSignatureGenerator(
    private val derGenerator: SignatureGenerator,
    private val curveOrderSize: Int,
) : SignatureGenerator {
    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray {
        val derSignature = derGenerator.generateSignatureBlocking(dataInput)

        val signature = DER.decodeFromByteArray(EcdsaSignatureValue.serializer(), derSignature)

        val r = signature.r.encodeToByteArray().trimLeadingZeros()
        val s = signature.s.encodeToByteArray().trimLeadingZeros()

        val rawSignature = ByteArray(curveOrderSize * 2)

        r.copyInto(rawSignature, curveOrderSize - r.size)
        s.copyInto(rawSignature, curveOrderSize * 2 - s.size)

        return rawSignature
    }
}

private class EcdsaRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val curveOrderSize: Int,
) : SignatureVerifier {
    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        check(signatureInput.size == curveOrderSize * 2) {
            "Expected signature size ${curveOrderSize * 2}, received: ${signatureInput.size}"
        }

        val r = signatureInput.copyOfRange(0, curveOrderSize).makePositive()
        val s = signatureInput.copyOfRange(curveOrderSize, signatureInput.size).makePositive()

        val signature = EcdsaSignatureValue(
            r = r.decodeToBigInt(),
            s = s.decodeToBigInt()
        )

        val derSignature = DER.encodeToByteArray(EcdsaSignatureValue.serializer(), signature)

        return derVerifier.verifySignatureBlocking(dataInput, derSignature)
    }
}

private fun ByteArray.makePositive(): ByteArray = if (this[0] < 0) byteArrayOf(0, *this) else this
