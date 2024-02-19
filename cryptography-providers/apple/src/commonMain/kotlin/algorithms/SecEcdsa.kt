/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

// TODO: check during decoding, that the curve is correct
// TODO: support encoding/decoding of keys :)
internal object SecEcdsa : ECDSA {
    private val EC.Curve.curveSize: Int
        get() = when (this) {
            EC.Curve.P256 -> 256
            EC.Curve.P384 -> 384
            EC.Curve.P521 -> 521
            else          -> error("Unsupported curve")
        }

    override fun publicKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        return EcdsaPublicKeyDecoder(curve.curveSize)
    }

    override fun privateKeyDecoder(curve: EC.Curve): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        return EcdsaPrivateKeyDecoder(curve.curveSize)
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> {
        return EcdsaKeyPairGenerator(curve.curveSize)
    }
}

private class EcdsaPublicKeyDecoder(
    private val curve: Int,
) : KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
    override fun decodeFromBlocking(format: EC.PublicKey.Format, input: ByteArray): ECDSA.PublicKey = when (format) {
        EC.PublicKey.Format.RAW -> TODO()
        EC.PublicKey.Format.DER -> TODO()
        EC.PublicKey.Format.PEM -> TODO()
        EC.PublicKey.Format.JWK -> TODO()
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPkcs1(input: NSData): ECDSA.PublicKey = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECDSA)
            add(kSecAttrKeyClass, kSecAttrKeyClassPublic)
        }.use { attributes ->

            val error = alloc<CFErrorRefVar>()

            val publicKey = SecKeyCreateWithData(
                input.retainBridgeAs<CFDataRef>(),
                attributes,
                error.ptr
            )
            if (publicKey == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to decode public key: ${nsError?.description}")
            }

            EcdsaPublicKey(publicKey)
        }
    }
}

private class EcdsaPrivateKeyDecoder(
    private val curve: Int,
) : KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
    override fun decodeFromBlocking(format: EC.PrivateKey.Format, input: ByteArray): ECDSA.PrivateKey = when (format) {
        EC.PrivateKey.Format.DER      -> TODO()
        EC.PrivateKey.Format.PEM      -> TODO()
        EC.PrivateKey.Format.JWK      -> TODO()
        EC.PrivateKey.Format.DER.SEC1 -> TODO()
        EC.PrivateKey.Format.PEM.SEC1 -> TODO()
        EC.PrivateKey.Format.RAW      -> TODO()
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPkcs1(input: NSData): ECDSA.PrivateKey = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECDSA)
            add(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        }.use { attributes ->

            val error = alloc<CFErrorRefVar>()

            val privateKey = SecKeyCreateWithData(
                input.retainBridgeAs<CFDataRef>(),
                attributes,
                error.ptr
            )
            if (privateKey == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to decode private key: ${nsError?.description}")
            }

            EcdsaPrivateKey(privateKey)
        }
    }
}

private class EcdsaKeyPairGenerator(
    private val curve: Int,
) : KeyGenerator<ECDSA.KeyPair> {

    @OptIn(UnsafeNumber::class)
    override fun generateKeyBlocking(): ECDSA.KeyPair = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeECDSA)
            @Suppress("CAST_NEVER_SUCCEEDS")
            add(kSecAttrKeySizeInBits, (curve as NSNumber).retainBridge())
        }.use { attributes ->
            val error = alloc<CFErrorRefVar>()

            val privateKey = SecKeyCreateRandomKey(
                parameters = attributes,
                error = error.ptr
            )
            if (privateKey == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to generate key pair: ${nsError?.description}")
            }
            val publicKey = SecKeyCopyPublicKey(privateKey)

            EcdsaKeyPair(
                EcdsaPublicKey(publicKey!!),
                EcdsaPrivateKey(privateKey)
            )
        }
    }
}

private class EcdsaKeyPair(
    override val publicKey: ECDSA.PublicKey,
    override val privateKey: ECDSA.PrivateKey,
) : ECDSA.KeyPair

private class EcdsaPublicKey(
    private val publicKey: SecKeyRef,
) : ECDSA.PublicKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(publicKey, SecKeyRef::release)

    override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
        check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
        return EcdsaSignatureVerifier(publicKey, digest.ecdsaSecKeyAlgorithm())
    }

    override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
        EC.PublicKey.Format.RAW -> encodeToRaw().toByteArray() //04 || X || Y
        EC.PublicKey.Format.DER -> TODO() // just wrap :)
        EC.PublicKey.Format.PEM -> TODO()
        EC.PublicKey.Format.JWK -> TODO()
    }

    private fun encodeToRaw(): NSData = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(publicKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey
    }
}

private class EcdsaPrivateKey(
    private val privateKey: SecKeyRef,
) : ECDSA.PrivateKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(privateKey, SecKeyRef::release)

    override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
        check(format == ECDSA.SignatureFormat.RAW) { "Only RAW signature format is supported" }
        return EcdsaSignatureGenerator(privateKey, digest.ecdsaSecKeyAlgorithm())
    }

    // the output is formatted as the public key concatenated with the big endian encoding of the secret scalar, or 04 || X || Y || K
    override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
        EC.PrivateKey.Format.DER      -> TODO()
        EC.PrivateKey.Format.PEM      -> TODO()
        EC.PrivateKey.Format.JWK      -> TODO()
        EC.PrivateKey.Format.DER.SEC1 -> TODO()
        EC.PrivateKey.Format.PEM.SEC1 -> TODO()
        EC.PrivateKey.Format.RAW      -> TODO()
    }

    private fun encodeToPkcs1(): NSData = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(privateKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey
    }
}

private class EcdsaSignatureGenerator(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureGenerator {
    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        dataInput.useNSData { data ->
            val signature = SecKeyCreateSignature(
                key = privateKey,
                algorithm = algorithm,
                dataToSign = data.retainBridgeAs<CFDataRef>(),
                error = error.ptr
            )?.releaseBridgeAs<NSData>()

            if (signature == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to generate signature: ${nsError?.description}")
            }

            signature.toByteArray()
        }
    }
}

private class EcdsaSignatureVerifier(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureVerifier {
    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = memScoped {
        val error = alloc<CFErrorRefVar>()
        dataInput.useNSData { data ->
            signatureInput.useNSData { signature ->
                val result = SecKeyVerifySignature(
                    key = publicKey,
                    algorithm = algorithm,
                    signedData = data.retainBridgeAs<CFDataRef>(),
                    error = error.ptr,
                    signature = signature.retainBridgeAs<CFDataRef>()
                )
                if (!result) {
                    val nsError = error.value.releaseBridgeAs<NSError>()
                    error("Failed to verify signature: ${nsError?.description}")
                }
                result
            }
        }
    }
}
