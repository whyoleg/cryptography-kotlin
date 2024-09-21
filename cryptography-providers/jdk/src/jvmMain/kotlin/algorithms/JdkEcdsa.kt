/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.functions.*
import dev.whyoleg.cryptography.operations.*
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
    override fun createSignFunction(): SignFunction = RawSignFunction(derGenerator.createSignFunction(), curveOrderSize)

    private class RawSignFunction(
        private val derSignFunction: SignFunction,
        private val curveOrderSize: Int,
    ) : SignFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derSignFunction.update(source, startIndex, endIndex)
        }

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val signature = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
            signature.copyInto(destination, destinationOffset, destinationOffset)
            return signature.size
        }

        override fun signToByteArray(): ByteArray {
            val derSignature = derSignFunction.signToByteArray()

            val signatureValue = Der.decodeFromByteArray(EcdsaSignatureValue.serializer(), derSignature)

            val r = signatureValue.r.encodeToByteArray().trimLeadingZeros()
            val s = signatureValue.s.encodeToByteArray().trimLeadingZeros()

            val rawSignature = ByteArray(curveOrderSize * 2)

            r.copyInto(rawSignature, curveOrderSize - r.size)
            s.copyInto(rawSignature, curveOrderSize * 2 - s.size)

            return rawSignature
        }

        override fun close() {
            derSignFunction.close()
        }
    }
}

private class EcdsaRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val curveOrderSize: Int,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = RawVerifyFunction(derVerifier.createVerifyFunction(), curveOrderSize)

    private class RawVerifyFunction(
        private val derVerifyFunction: VerifyFunction,
        private val curveOrderSize: Int,
    ) : VerifyFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derVerifyFunction.update(source, startIndex, endIndex)
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            check((endIndex - startIndex) == curveOrderSize * 2) {
                "Expected signature size ${curveOrderSize * 2}, received: ${endIndex - startIndex}"
            }

            val r = signature.copyOfRange(startIndex, startIndex + curveOrderSize).makePositive()
            val s = signature.copyOfRange(startIndex + curveOrderSize, endIndex).makePositive()

            val signatureValue = EcdsaSignatureValue(
                r = r.decodeToBigInt(),
                s = s.decodeToBigInt()
            )

            val derSignature = Der.encodeToByteArray(EcdsaSignatureValue.serializer(), signatureValue)

            return derVerifyFunction.tryVerify(derSignature)
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun close() {
            derVerifyFunction.close()
        }
    }
}

private fun ByteArray.makePositive(): ByteArray = if (this[0] < 0) byteArrayOf(0, *this) else this
