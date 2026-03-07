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

// Shared DER <-> RAW (r || s) signature format conversion for DSA and ECDSA.
// Both use the same ASN.1 structure: SEQUENCE { r INTEGER, s INTEGER }.
// The `orderSize` parameter is the subprime q size (DSA) or curve order size (ECDSA).

@CryptographyProviderApi
public fun convertDssDerSignatureToRaw(orderSize: Int, derSignature: ByteArray): ByteArray {
    val signatureValue = Der.decodeFromByteArray(DssSignatureValue.serializer(), derSignature)

    val r = signatureValue.r.magnitudeToByteArray()
    val s = signatureValue.s.magnitudeToByteArray()

    val rawSignature = ByteArray(orderSize * 2)

    r.copyInto(rawSignature, orderSize - r.size)
    s.copyInto(rawSignature, orderSize * 2 - s.size)

    return rawSignature
}

@CryptographyProviderApi
public fun convertDssRawSignatureToDer(
    orderSize: Int,
    rawSignature: ByteArray,
    startIndex: Int,
    endIndex: Int,
): ByteArray {
    check((endIndex - startIndex) == orderSize * 2) {
        "Expected signature size ${orderSize * 2}, received: ${endIndex - startIndex}"
    }

    val signatureValue = DssSignatureValue(
        r = BigInt.fromMagnitude(sign = 1, rawSignature.copyOfRange(startIndex, startIndex + orderSize)),
        s = BigInt.fromMagnitude(sign = 1, rawSignature.copyOfRange(startIndex + orderSize, endIndex)),
    )

    return Der.encodeToByteArray(DssSignatureValue.serializer(), signatureValue)
}

@CryptographyProviderApi
public class DssRawSignatureGenerator(
    private val derGenerator: SignatureGenerator,
    private val orderSize: Int,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = RawSignFunction(derGenerator.createSignFunction(), orderSize)

    private class RawSignFunction(
        private val derSignFunction: SignFunction,
        private val orderSize: Int,
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
            return convertDssDerSignatureToRaw(orderSize, derSignFunction.signToByteArray())
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
public class DssRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val orderSize: Int,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = RawVerifyFunction(derVerifier.createVerifyFunction(), orderSize)

    private class RawVerifyFunction(
        private val derVerifyFunction: VerifyFunction,
        private val orderSize: Int,
    ) : VerifyFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derVerifyFunction.update(source, startIndex, endIndex)
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            return derVerifyFunction.tryVerify(
                convertDssRawSignatureToDer(orderSize, signature, startIndex, endIndex),
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
