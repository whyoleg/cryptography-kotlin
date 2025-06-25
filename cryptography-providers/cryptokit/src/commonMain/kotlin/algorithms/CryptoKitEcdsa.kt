/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import dev.whyoleg.cryptography.providers.cryptokit.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitEcdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        return PublicKeyDecoder(curve.swiftEcCurve())
    }

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        return PrivateKeyDecoder(curve.swiftEcCurve())
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> {
        return KeyPairGenerator(curve.swiftEcCurve())
    }

    private class KeyPairGenerator(
        private val curve: SwiftEcCurve,
    ) : KeyGenerator<ECDSA.KeyPair> {
        override fun generateKeyBlocking(): ECDSA.KeyPair {
            val privateKey = SwiftEcdsaPrivateKey.generateWithCurve(curve)
            return EcdsaKeyPair(
                privateKey = EcdsaPrivateKey(privateKey),
                publicKey = EcdsaPublicKey(privateKey.publicKey())
            )
        }
    }

    private class PublicKeyDecoder(
        private val curve: SwiftEcCurve,
    ) : KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDSA.PublicKey {
            return EcdsaPublicKey(swiftTry { error ->
                when (format) {
                    EC.PublicKey.Format.JWK -> error("JWK is not supported")
                    EC.PublicKey.Format.RAW -> bytes.useNSData { SwiftEcdsaPublicKey.decodeRawWithCurve(curve, it, error) }
                    EC.PublicKey.Format.RAW.Compressed -> bytes.useNSData { SwiftEcdsaPublicKey.decodeRawCompressedWithCurve(curve, it, error) }
                    EC.PublicKey.Format.DER -> bytes.useNSData { SwiftEcdsaPublicKey.decodeDerWithCurve(curve, it, error) }
                    EC.PublicKey.Format.PEM -> SwiftEcdsaPublicKey.decodePemWithCurve(curve, bytes.decodeToString(), error)
                }
            })
        }
    }

    private class PrivateKeyDecoder(
        private val curve: SwiftEcCurve,
    ) : KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDSA.PrivateKey {
            return EcdsaPrivateKey(swiftTry { error ->
                when (format) {
                    EC.PrivateKey.Format.JWK      -> error("JWK is not supported")
                    EC.PrivateKey.Format.RAW      -> bytes.useNSData { SwiftEcdsaPrivateKey.decodeRawWithCurve(curve, it, error) }
                    EC.PrivateKey.Format.DER      -> decodeFromDer(bytes, error)
                    EC.PrivateKey.Format.DER.SEC1 -> decodeFromDer(convertEcPrivateKeyFromSec1ToPkcs8(bytes), error)
                    EC.PrivateKey.Format.PEM,
                    EC.PrivateKey.Format.PEM.SEC1,
                                                  -> SwiftEcdsaPrivateKey.decodePemWithCurve(curve, bytes.decodeToString(), error)
                }
            })
        }

        private fun decodeFromDer(bytes: ByteArray, error: SwiftErrorPointer): SwiftEcdsaPrivateKey? {
            return bytes.useNSData { SwiftEcdsaPrivateKey.decodeDerWithCurve(curve, it, error) }
        }
    }
}

private class EcdsaKeyPair(
    override val privateKey: ECDSA.PrivateKey,
    override val publicKey: ECDSA.PublicKey,
) : ECDSA.KeyPair

@OptIn(UnsafeNumber::class)
private class EcdsaPublicKey(
    private val publicKey: SwiftEcdsaPublicKey,
) : ECDSA.PublicKey {
    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.JWK -> error("JWK is not supported")
        EC.PublicKey.Format.RAW -> publicKey.rawRepresentation().toByteArray()
        EC.PublicKey.Format.RAW.Compressed -> publicKey.compressedRepresentation().toByteArray()
        EC.PublicKey.Format.DER -> publicKey.derRepresentation().toByteArray()
        EC.PublicKey.Format.PEM -> (publicKey.pemRepresentation() + "\n").encodeToByteArray()
    }

    override fun signatureVerifier(
        digest: CryptographyAlgorithmId<Digest>,
        format: ECDSA.SignatureFormat,
    ): SignatureVerifier = EcdsaSignatureVerifier(
        algorithm = digest.swiftHashAlgorithm(),
        publicKey = publicKey,
        format = format
    )
}

@OptIn(UnsafeNumber::class)
private class EcdsaPrivateKey(
    private val privateKey: SwiftEcdsaPrivateKey,
) : ECDSA.PrivateKey {
    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.JWK      -> error("JWK is not supported")
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
        digest: CryptographyAlgorithmId<Digest>,
        format: ECDSA.SignatureFormat,
    ): SignatureGenerator = EcdsaSignatureGenerator(
        algorithm = digest.swiftHashAlgorithm(),
        privateKey = privateKey,
        format = format
    )
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignatureGenerator(
    private val algorithm: SwiftHashAlgorithm,
    private val privateKey: SwiftEcdsaPrivateKey,
    private val format: ECDSA.SignatureFormat,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = EcdsaSignFunction(algorithm, privateKey, format)
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignatureVerifier(
    private val algorithm: SwiftHashAlgorithm,
    private val publicKey: SwiftEcdsaPublicKey,
    private val format: ECDSA.SignatureFormat,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = EcdsaVerifyFunction(algorithm, publicKey, format)
}

@OptIn(UnsafeNumber::class)
private class EcdsaSignFunction(
    algorithm: SwiftHashAlgorithm,
    private val privateKey: SwiftEcdsaPrivateKey,
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
    algorithm: SwiftHashAlgorithm,
    private val publicKey: SwiftEcdsaPublicKey,
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
