/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.providers.cryptokit.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitEcdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve): Decoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        return PublicKeyDecoder(curve)
    }

    override fun privateKeyDecoder(curve: EC.Curve): Decoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        return PrivateKeyDecoder(curve)
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> {
        return KeyPairGenerator(curve)
    }

    private class KeyPairGenerator(
        private val curve: EC.Curve,
    ) : KeyGenerator<ECDSA.KeyPair> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun generateKeyBlocking(): ECDSA.KeyPair {
            val privateKey = DwcEcdsaPrivateKey.generateWithCurve(swiftCurve)
            return EcdsaKeyPair(
                privateKey = EcdsaPrivateKey(curve, privateKey),
                publicKey = EcdsaPublicKey(curve, privateKey.publicKey())
            )
        }
    }

    private class PublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Decoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDSA.PublicKey {
            return EcdsaPublicKey(curve, swiftTry { error ->
                when (format) {
                    EC.PublicKey.Format.JWK            -> {
                        val rawKey = JsonWebKeys.decodeEcPublicKey(curve, curve.orderSize(), bytes)
                        rawKey.useNSData { DwcEcdsaPublicKey.decodeRawWithCurve(swiftCurve, it, error) }
                    }
                    EC.PublicKey.Format.RAW            -> bytes.useNSData { DwcEcdsaPublicKey.decodeRawWithCurve(swiftCurve, it, error) }
                    EC.PublicKey.Format.RAW.Compressed -> bytes.useNSData {
                        DwcEcdsaPublicKey.decodeRawCompressedWithCurve(
                            swiftCurve,
                            it,
                            error
                        )
                    }
                    EC.PublicKey.Format.DER            -> bytes.useNSData { DwcEcdsaPublicKey.decodeDerWithCurve(swiftCurve, it, error) }
                    EC.PublicKey.Format.PEM            -> DwcEcdsaPublicKey.decodePemWithCurve(swiftCurve, bytes.decodeToString(), error)
                }
            })
        }
    }

    private class PrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Decoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        private val swiftCurve get() = curve.swiftEcCurve()

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDSA.PrivateKey {
            return EcdsaPrivateKey(curve, swiftTry { error ->
                when (format) {
                    EC.PrivateKey.Format.JWK -> {
                        val rawKey = JsonWebKeys.decodeEcPrivateKey(curve, curve.orderSize(), bytes).privateKey
                        rawKey.useNSData { DwcEcdsaPrivateKey.decodeRawWithCurve(swiftCurve, it, error) }
                    }
                    EC.PrivateKey.Format.RAW -> bytes.useNSData { DwcEcdsaPrivateKey.decodeRawWithCurve(swiftCurve, it, error) }
                    EC.PrivateKey.Format.DER      -> decodeFromDer(bytes, error)
                    EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(bytes), error)
                    EC.PrivateKey.Format.PEM,
                    EC.PrivateKey.Format.PEM.SEC1,
                                             -> DwcEcdsaPrivateKey.decodePemWithCurve(swiftCurve, bytes.decodeToString(), error)
                }
            })
        }

        private fun decodeFromDer(bytes: ByteArray, error: DwcErrorPointer): DwcEcdsaPrivateKey? {
            return bytes.useNSData { DwcEcdsaPrivateKey.decodeDerWithCurve(swiftCurve, it, error) }
        }
    }
}

private class EcdsaKeyPair(
    override val privateKey: ECDSA.PrivateKey,
    override val publicKey: ECDSA.PublicKey,
) : ECDSA.KeyPair

@OptIn(UnsafeNumber::class)
private class EcdsaPublicKey(
    private val curve: EC.Curve,
    private val publicKey: DwcEcdsaPublicKey,
) : ECDSA.PublicKey {
    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> JsonWebKeys.encodeEcPublicKey(
            curve = curve,
            orderSize = curve.orderSize(),
            publicKey = publicKey.rawRepresentation().toByteArray()
        )
        EC.PublicKey.Format.RAW -> publicKey.rawRepresentation().toByteArray()
        EC.PublicKey.Format.RAW.Compressed -> swiftTry { error -> publicKey.compressedRepresentationAndReturnError(error)?.toByteArray() }
        EC.PublicKey.Format.DER -> publicKey.derRepresentation().toByteArray()
        EC.PublicKey.Format.PEM -> (publicKey.pemRepresentation() + "\n").encodeToByteArray()
    }

    override fun signatureVerifier(
        digest: CryptographyAlgorithmId<Digest>?,
        format: ECDSA.SignatureFormat,
    ): SignatureVerifier = EcdsaSignatureVerifier(
        algorithm = digest.swiftHashAlgorithm(),
        publicKey = publicKey,
        format = format
    )
}

@OptIn(UnsafeNumber::class)
private class EcdsaPrivateKey(
    private val curve: EC.Curve,
    private val privateKey: DwcEcdsaPrivateKey,
) : ECDSA.PrivateKey {
    override fun getPublicKeyBlocking(): ECDSA.PublicKey = EcdsaPublicKey(curve, privateKey.publicKey())

    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK -> JsonWebKeys.encodeEcPrivateKey(
            curve = curve,
            orderSize = curve.orderSize(),
            publicKey = privateKey.publicKey().rawRepresentation().toByteArray(),
            privateKey = privateKey.rawRepresentation().toByteArray()
        )
        EC.PrivateKey.Format.RAW      -> privateKey.rawRepresentation().toByteArray()
        EC.PrivateKey.Format.DER      -> privateKey.derRepresentation().toByteArray()
        EC.PrivateKey.Format.DER.SEC1 -> convertEcPrivateKeyFromPkcs8ToSec1(privateKey.derRepresentation().toByteArray())
        EC.PrivateKey.Format.PEM      -> (privateKey.pemRepresentation() + "\n").encodeToByteArray()
        EC.PrivateKey.Format.PEM.SEC1 -> wrapPem(
            PemLabel.EcPrivateKey,
            convertEcPrivateKeyFromPkcs8ToSec1(privateKey.derRepresentation().toByteArray())
        )
    }

    override fun signatureGenerator(
        digest: CryptographyAlgorithmId<Digest>?,
        format: ECDSA.SignatureFormat,
    ): SignatureGenerator = EcdsaSignatureGenerator(
        algorithm = digest.swiftHashAlgorithm(),
        privateKey = privateKey,
        format = format
    )
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignatureGenerator(
    private val algorithm: DwcHashAlgorithm,
    private val privateKey: DwcEcdsaPrivateKey,
    private val format: ECDSA.SignatureFormat,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = EcdsaSignFunction(algorithm, privateKey, format)
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignatureVerifier(
    private val algorithm: DwcHashAlgorithm,
    private val publicKey: DwcEcdsaPublicKey,
    private val format: ECDSA.SignatureFormat,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = EcdsaVerifyFunction(algorithm, publicKey, format)
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignFunction(
    algorithm: DwcHashAlgorithm,
    private val privateKey: DwcEcdsaPrivateKey,
    private val format: ECDSA.SignatureFormat,
) : HashBasedFunction(algorithm), SignFunction {
    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        return signToNSData().getIntoByteArray(destination, destinationOffset)
    }

    override fun signToByteArray(): ByteArray {
        return signToNSData().toByteArray()
    }

    private fun signToNSData(): NSData {
        val digest = function.doFinalDigest()
        reset()
        return swiftTry { error ->
            when (format) {
                ECDSA.SignatureFormat.RAW -> privateKey.signRawWithDigest(digest, error)
                ECDSA.SignatureFormat.DER -> privateKey.signDerWithDigest(digest, error)
            }
        }
    }
}

@OptIn(UnsafeNumber::class)
private class EcdsaVerifyFunction(
    algorithm: DwcHashAlgorithm,
    private val publicKey: DwcEcdsaPublicKey,
    private val format: ECDSA.SignatureFormat,
) : HashBasedFunction(algorithm), VerifyFunction {
    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        val digest = function.doFinalDigest()
        reset()
        return signature.useNSData(startIndex, endIndex) { signatureData ->
            when (format) {
                ECDSA.SignatureFormat.RAW -> publicKey.verifyRawWithSignature(signatureData, digest)
                ECDSA.SignatureFormat.DER -> publicKey.verifyDerWithSignature(signatureData, digest)
            }
        }
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }
}

