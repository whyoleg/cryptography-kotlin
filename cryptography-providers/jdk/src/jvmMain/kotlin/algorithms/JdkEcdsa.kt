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
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
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
        val verifier = JdkSignatureVerifier(state, key, digest.hashAlgorithmName() + "withECDSA", null)
        return when (format) {
            ECDSA.SignatureFormat.DER -> verifier
            ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(verifier, curveOrderSize(key as ECKey))
        }
    }

    override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> error("$format is not supported")
        EC.PublicKey.Format.RAW -> {
            key as ECPublicKey

            val fieldSize = curveOrderSize(key)
            val x = key.w.affineX.toByteArray().trimLeadingZeros()
            val y = key.w.affineY.toByteArray().trimLeadingZeros()
            check(x.size <= fieldSize && y.size <= fieldSize)

            val output = ByteArray(fieldSize * 2 + 1)
            output[0] = 4 // uncompressed
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
        val generator = JdkSignatureGenerator(state, key, digest.hashAlgorithmName() + "withECDSA", null)
        return when (format) {
            ECDSA.SignatureFormat.DER -> generator
            ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(generator, curveOrderSize(key as ECKey))
        }
    }

    override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK -> error("$format is not supported")
        EC.PrivateKey.Format.DER -> encodeToDer()
        EC.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        EC.PrivateKey.Format.DER.SEC1 -> convertPkcs8ToSec1(encodeToDer())
        EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, convertPkcs8ToSec1(encodeToDer()))
    }

    private fun convertPkcs8ToSec1(input: ByteArray): ByteArray {
        val privateKeyInfo = DER.decodeFromByteArray(PrivateKeyInfo.serializer(), input)

        val privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm
        check(privateKeyAlgorithm is EcKeyAlgorithmIdentifier) {
            "Expected algorithm '${ObjectIdentifier.EC}', received: '${privateKeyAlgorithm.algorithm}'"
        }
        // the produced key could not contain parameters in underlying EcPrivateKey,
        // but they are available in `privateKeyAlgorithm`
        val ecPrivateKey = DER.decodeFromByteArray(EcPrivateKey.serializer(), privateKeyInfo.privateKey)
        if (ecPrivateKey.parameters != null) return privateKeyInfo.privateKey

        val enhancedEcPrivateKey = EcPrivateKey(
            version = ecPrivateKey.version,
            privateKey = ecPrivateKey.privateKey,
            parameters = privateKeyAlgorithm.parameters,
            publicKey = ecPrivateKey.publicKey
        )
        return DER.encodeToByteArray(EcPrivateKey.serializer(), enhancedEcPrivateKey)
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

private fun curveOrderSize(key: ECKey): Int {
    return (key.params.curve.field.fieldSize + 7) / 8
}

private fun ByteArray.makePositive(): ByteArray = if (this[0] < 0) byteArrayOf(0, *this) else this

private fun ByteArray.trimLeadingZeros(): ByteArray {
    val firstNonZeroIndex = indexOfFirst { it != 0.toByte() }
    if (firstNonZeroIndex == -1) return this
    return copyOfRange(firstNonZeroIndex, size)
}
