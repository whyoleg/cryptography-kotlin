/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.security.interfaces.*

internal class JdkEcdsa(state: JdkCryptographyState) : JdkEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(state), ECDSA {
    override fun JPublicKey.convert(): ECDSA.PublicKey = EcdsaPublicKey(state, this)
    override fun JPrivateKey.convert(): ECDSA.PrivateKey = EcdsaPrivateKey(state, this)
    override fun JKeyPair.convert(): ECDSA.KeyPair = EcdsaKeyPair(public.convert(), private.convert())
}

private class EcdsaKeyPair(
    override val publicKey: ECDSA.PublicKey,
    override val privateKey: ECDSA.PrivateKey,
) : ECDSA.KeyPair

private class EcdsaPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : ECDSA.PublicKey, JdkEncodableKey<EC.PublicKey.Format>(key, "EC") {
    override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
        return JdkSignatureVerifier(state, key, digest.hashAlgorithmName() + "withECDSA" + format.algorithmSuffix(), null)
    }

    override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> error("$format is not supported")
        EC.PublicKey.Format.RAW -> {
            key as ECPublicKey

            val point = key.w
            val fieldSize = (key.params.curve.field.fieldSize + 7) / 8
            val output = ByteArray(fieldSize * 2 + 1)
            output[0] = 4

            val x = point.affineX.toByteArray().trimLeadingZeros()
            val y = point.affineY.toByteArray().trimLeadingZeros()
            check(x.size <= fieldSize && y.size <= fieldSize)

            x.copyInto(output, fieldSize - x.size + 1)
            y.copyInto(output, fieldSize * 2 - y.size + 1)

            output
        }
        EC.PublicKey.Format.DER -> encodeToDer()
        EC.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
    }
}

private class EcdsaPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : ECDSA.PrivateKey, JdkEncodableKey<EC.PrivateKey.Format>(key, "EC") {
    override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
        return JdkSignatureGenerator(state, key, digest.hashAlgorithmName() + "withECDSA" + format.algorithmSuffix(), null)
    }

    override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK -> error("$format is not supported")
        EC.PrivateKey.Format.DER -> encodeToDer()
        EC.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
    }
}

private fun ECDSA.SignatureFormat.algorithmSuffix() = when (this) {
    ECDSA.SignatureFormat.RAW -> "inP1363Format"
    ECDSA.SignatureFormat.DER -> ""
}

private fun ByteArray.trimLeadingZeros(): ByteArray {
    val firstNonZeroIndex = indexOfFirst { it != 0.toByte() }
    if (firstNonZeroIndex == -1) return this
    return copyOfRange(firstNonZeroIndex, size)
}
