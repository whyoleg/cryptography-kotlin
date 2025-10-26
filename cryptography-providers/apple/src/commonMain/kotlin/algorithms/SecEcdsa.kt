/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

private class EcCurveData private constructor(
    val size: Int,
    val orderSize: Int,
    val curve: ObjectIdentifier,
) {
    companion object {
        val P256 = EcCurveData(256, 32, ObjectIdentifier.secp256r1)
        val P384 = EcCurveData(384, 48, ObjectIdentifier.secp384r1)
        val P521 = EcCurveData(521, 66, ObjectIdentifier.secp521r1)

        operator fun invoke(curve: EC.Curve): EcCurveData = when (curve) {
            EC.Curve.P256 -> P256
            EC.Curve.P384 -> P384
            EC.Curve.P521 -> P521
            else          -> error("Unsupported curve: ${curve.name}")
        }
    }
}

internal object SecEcdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        return EcdsaPublicKeyDecoder(EcCurveData(curve))
    }

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        return EcdsaPrivateKeyDecoder(EcCurveData(curve))
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> {
        return EcdsaKeyPairGenerator(EcCurveData(curve))
    }
}

private class EcdsaPublicKeyDecoder(
    private val curve: EcCurveData,
) : KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
    override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDSA.PublicKey {
        val rawKey = when (format) {
            EC.PublicKey.Format.JWK            -> error("$format is not supported")
            EC.PublicKey.Format.RAW            -> bytes
            EC.PublicKey.Format.RAW.Compressed -> error("$format is not supported")
            EC.PublicKey.Format.DER            -> decodeDer(bytes)
            EC.PublicKey.Format.PEM            -> decodeDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
        check(rawKey.size == curve.orderSize * 2 + 1) {
            "Invalid raw key size: ${rawKey.size}, expected: ${curve.orderSize * 2 + 1}"
        }

        val secKey = CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            add(kSecAttrKeyClass, kSecAttrKeyClassPublic)
        }.use { attributes ->
            decodeSecKey(rawKey, attributes)
        }
        return EcdsaPublicKey(secKey, curve)
    }

    private fun decodeDer(input: ByteArray): ByteArray {
        val spki = Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), input)
        ensureCurve(spki.algorithm, curve)
        return spki.subjectPublicKey.toByteArray()
    }
}

private class EcdsaPrivateKeyDecoder(
    private val curve: EcCurveData,
) : KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
    override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDSA.PrivateKey {
        val rawKey = when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.RAW      -> error("$format is not supported")
            EC.PrivateKey.Format.DER      -> decodeDerPkcs8(bytes)
            EC.PrivateKey.Format.PEM      -> decodeDerPkcs8(unwrapPem(PemLabel.PrivateKey, bytes))
            EC.PrivateKey.Format.DER.SEC1 -> decodeDerSec1(bytes)
            EC.PrivateKey.Format.PEM.SEC1 -> decodeDerSec1(unwrapPem(PemLabel.EcPrivateKey, bytes))
        }
        check(rawKey.size == curve.orderSize * 3 + 1) {
            "Invalid raw key size: ${rawKey.size}, expected: ${curve.orderSize * 3 + 1}"
        }

        val secKey = CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            add(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        }.use { attributes ->
            decodeSecKey(rawKey, attributes)
        }
        return EcdsaPrivateKey(secKey, curve)
    }

    private fun decodeDerPkcs8(input: ByteArray): ByteArray {
        val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)
        ensureCurve(pki.privateKeyAlgorithm, curve)
        val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), pki.privateKey)
        return ecPrivateKey.convertToRawKey()
    }

    private fun decodeDerSec1(input: ByteArray): ByteArray {
        val ecPrivateKey = Der.decodeFromByteArray(EcPrivateKey.serializer(), input)
        ensureCurve(ecPrivateKey.parameters, curve)
        return ecPrivateKey.convertToRawKey()
    }

    private fun EcPrivateKey.convertToRawKey(): ByteArray {
        val publicKey = publicKey?.toByteArray()
            ?: error("publicKey should be present in EcPrivateKey representation")
        val rawKey = ByteArray(curve.orderSize * 3 + 1)
        publicKey.copyInto(rawKey)
        privateKey.copyInto(rawKey, curve.orderSize * 3 + 1 - privateKey.size)
        return rawKey
    }
}

private class EcdsaKeyPairGenerator(
    private val curve: EcCurveData,
) : KeyGenerator<ECDSA.KeyPair> {

    override fun generateKeyBlocking(): ECDSA.KeyPair {
        val privateKey = CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            @Suppress("CAST_NEVER_SUCCEEDS")
            add(kSecAttrKeySizeInBits, (curve.size as NSNumber).retainBridge())
        }.use { attributes ->
            generateSecKey(attributes)
        }

        val publicKey = SecKeyCopyPublicKey(privateKey)!!
        return EcdsaKeyPair(
            EcdsaPublicKey(publicKey, curve),
            EcdsaPrivateKey(privateKey, curve)
        )
    }
}

private class EcdsaKeyPair(
    override val publicKey: ECDSA.PublicKey,
    override val privateKey: ECDSA.PrivateKey,
) : ECDSA.KeyPair

private class EcdsaPublicKey(
    private val publicKey: SecKeyRef,
    private val curve: EcCurveData,
) : ECDSA.PublicKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(publicKey, SecKeyRef::release)

    override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
        val verifier = SecSignatureVerifier(publicKey, digest.ecdsaSecKeyAlgorithm())
        return when (format) {
            ECDSA.SignatureFormat.DER -> verifier
            ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(verifier, curve.orderSize)
        }
    }

    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray {
        val rawKey = exportSecKey(publicKey)

        return when (format) {
            EC.PublicKey.Format.JWK            -> error("$format is not supported")
            EC.PublicKey.Format.RAW            -> rawKey
            EC.PublicKey.Format.RAW.Compressed -> error("$format is not supported")
            EC.PublicKey.Format.DER            -> encodeDer(rawKey)
            EC.PublicKey.Format.PEM            -> wrapPem(PemLabel.PublicKey, encodeDer(rawKey))
        }
    }

    private fun encodeDer(rawKey: ByteArray): ByteArray {
        val spki = SubjectPublicKeyInfo(
            algorithm = EcKeyAlgorithmIdentifier(EcParameters(curve.curve)),
            subjectPublicKey = rawKey.toBitArray(),
        )

        return Der.encodeToByteArray(SubjectPublicKeyInfo.serializer(), spki)
    }
}

private class EcdsaPrivateKey(
    private val privateKey: SecKeyRef,
    private val curve: EcCurveData,
) : ECDSA.PrivateKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(privateKey, SecKeyRef::release)

    override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
        val generator = SecSignatureGenerator(privateKey, digest.ecdsaSecKeyAlgorithm())
        return when (format) {
            ECDSA.SignatureFormat.DER -> generator
            ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(generator, curve.orderSize)
        }
    }

    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray {
        val rawKey = exportSecKey(privateKey)
        return when (format) {
            EC.PrivateKey.Format.JWK      -> error("$format is not supported")
            EC.PrivateKey.Format.RAW      -> rawKey.copyOfRange(curve.orderSize * 2 + 1, curve.orderSize * 3 + 1)
            EC.PrivateKey.Format.DER      -> encodeDerPkcs8(rawKey)
            EC.PrivateKey.Format.PEM      -> wrapPem(PemLabel.PrivateKey, encodeDerPkcs8(rawKey))
            EC.PrivateKey.Format.DER.SEC1 -> encodeDerEcPrivateKey(rawKey)
            EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(PemLabel.EcPrivateKey, encodeDerEcPrivateKey(rawKey))
        }
    }

    private fun encodeDerPkcs8(rawKey: ByteArray): ByteArray {
        val pki = PrivateKeyInfo(
            version = 0,
            privateKeyAlgorithm = EcKeyAlgorithmIdentifier(EcParameters(curve.curve)),
            privateKey = encodeDerEcPrivateKey(rawKey)
        )
        return Der.encodeToByteArray(PrivateKeyInfo.serializer(), pki)
    }

    private fun encodeDerEcPrivateKey(rawKey: ByteArray): ByteArray {
        val ecPrivateKey = EcPrivateKey(
            version = 1,
            privateKey = rawKey.copyOfRange(curve.orderSize * 2 + 1, curve.orderSize * 3 + 1),
            parameters = EcParameters(curve.curve),
            publicKey = rawKey.copyOfRange(0, curve.orderSize * 2 + 1).toBitArray()
        )

        return Der.encodeToByteArray(EcPrivateKey.serializer(), ecPrivateKey)
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
            signature.copyInto(destination, destinationOffset, 0, signature.size)
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

        override fun reset() {
            derSignFunction.reset()
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

private fun ensureCurve(identifier: AlgorithmIdentifier, curve: EcCurveData) {
    check(identifier is EcKeyAlgorithmIdentifier) {
        "Expected algorithm `${ObjectIdentifier.EC}`, but was ${identifier.algorithm}"
    }
    ensureCurve(identifier.parameters, curve)
}

private fun ensureCurve(parameters: EcParameters?, curve: EcCurveData) {
    check(parameters?.namedCurve == curve.curve) {
        "Expected curve `${curve.curve}`, but was ${parameters?.namedCurve}"
    }
}

// TODO: recheck conversions
// TODO: shift on unused bits? or even redesign `BitArray`
private fun ByteArray.toBitArray(): BitArray = BitArray(0, this)
private fun BitArray.toByteArray(): ByteArray = byteArray
