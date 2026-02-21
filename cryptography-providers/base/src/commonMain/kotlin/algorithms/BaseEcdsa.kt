/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

@CryptographyProviderApi
public fun convertEcdsaDerSignatureToRaw(curveOrderSize: Int, derSignature: ByteArray): ByteArray {
    val signatureValue = Der.decodeFromByteArray(EcdsaSignatureValue.serializer(), derSignature)

    val r = signatureValue.r.encodeToByteArray().trimLeadingZeros()
    val s = signatureValue.s.encodeToByteArray().trimLeadingZeros()

    val rawSignature = ByteArray(curveOrderSize * 2)

    r.copyInto(rawSignature, curveOrderSize - r.size)
    s.copyInto(rawSignature, curveOrderSize * 2 - s.size)

    return rawSignature
}

@CryptographyProviderApi
public fun convertEcdsaRawSignatureToDer(
    curveOrderSize: Int,
    rawSignature: ByteArray,
    startIndex: Int,
    endIndex: Int,
): ByteArray {
    check((endIndex - startIndex) == curveOrderSize * 2) {
        "Expected signature size ${curveOrderSize * 2}, received: ${endIndex - startIndex}"
    }

    val r = rawSignature.copyOfRange(startIndex, startIndex + curveOrderSize).makePositive()
    val s = rawSignature.copyOfRange(startIndex + curveOrderSize, endIndex).makePositive()

    val signatureValue = EcdsaSignatureValue(
        r = r.decodeToBigInt(),
        s = s.decodeToBigInt()
    )

    return Der.encodeToByteArray(EcdsaSignatureValue.serializer(), signatureValue)
}

@CryptographyProviderApi
public class EcdsaRawSignatureGenerator(
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
            signature.copyInto(destination, destinationOffset)
            return signature.size
        }

        override fun signToByteArray(): ByteArray {
            return convertEcdsaDerSignatureToRaw(curveOrderSize, derSignFunction.signToByteArray())
        }

        override fun reset() {
            derSignFunction.reset()
        }

        override fun close() {
            derSignFunction.close()
        }
    }
}

@CryptographyProviderApi
public class EcdsaRawSignatureVerifier(
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

            return derVerifyFunction.tryVerify(
                convertEcdsaRawSignatureToDer(curveOrderSize, signature, startIndex, endIndex),
            )
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun reset() {
            derVerifyFunction.reset()
        }

        override fun close() {
            derVerifyFunction.close()
        }
    }
}

private fun ByteArray.makePositive(): ByteArray = if (this[0] < 0) byteArrayOf(0, *this) else this

private fun ByteArray.trimLeadingZeros(): ByteArray {
    val firstNonZeroIndex = indexOfFirst { it != 0.toByte() }
    if (firstNonZeroIndex == -1) return this
    return copyOfRange(firstNonZeroIndex, size)
}
