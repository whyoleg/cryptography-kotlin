/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object SecRsaPss : RSA.PSS {
    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PSS.PublicKey> =
        RsaPssPublicKeyDecoder(digest.rsaPssSecKeyAlgorithm())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        RsaPssPrivateKeyDecoder(digest.rsaPssSecKeyAlgorithm())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.PSS.KeyPair> {
        check(publicExponent == 65537.toBigInt()) { "Only F4 public exponent is supported" }

        return RsaPssKeyPairGenerator(keySize.inBits, digest.rsaPssSecKeyAlgorithm())
    }
}

private class RsaPssPublicKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PublicKey.Format, RSA.PSS.PublicKey> {
    override fun decodeFromBlocking(format: RSA.PublicKey.Format, input: ByteArray): RSA.PSS.PublicKey = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.DER_RSA -> input.useNSData(::decodeFromPss)
        RSA.PublicKey.Format.PEM_RSA -> PEM.decode(input).ensurePemLabel(PemLabel.RsaPublicKey).bytes.useNSData(::decodeFromPss)
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPss(input: NSData): RSA.PSS.PublicKey = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
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

            RsaPssPublicKey(publicKey, algorithm)
        }
    }
}

private class RsaPssPrivateKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> {
    override fun decodeFromBlocking(format: RSA.PrivateKey.Format, input: ByteArray): RSA.PSS.PrivateKey = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.DER_RSA -> input.useNSData(::decodeFromPss)
        RSA.PrivateKey.Format.PEM_RSA -> PEM.decode(input).ensurePemLabel(PemLabel.RsaPrivateKey).bytes.useNSData(::decodeFromPss)
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPss(input: NSData): RSA.PSS.PrivateKey = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
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

            RsaPssPrivateKey(privateKey, algorithm)
        }
    }
}

private class RsaPssKeyPairGenerator(
    private val keySizeBits: Int,
    private val algorithm: SecKeyAlgorithm?,
) : KeyGenerator<RSA.PSS.KeyPair> {

    @OptIn(UnsafeNumber::class)
    override fun generateKeyBlocking(): RSA.PSS.KeyPair = memScoped {
        CFMutableDictionary(2.convert()) {
            add(kSecAttrKeyType, kSecAttrKeyTypeRSA)
            @Suppress("CAST_NEVER_SUCCEEDS")
            add(kSecAttrKeySizeInBits, (keySizeBits as NSNumber).retainBridge())
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

            RsaPssKeyPair(
                RsaPssPublicKey(publicKey!!, algorithm),
                RsaPssPrivateKey(privateKey, algorithm)
            )
        }
    }
}

private class RsaPssKeyPair(
    override val publicKey: RSA.PSS.PublicKey,
    override val privateKey: RSA.PSS.PrivateKey,
) : RSA.PSS.KeyPair

private class RsaPssPublicKey(
    private val publicKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.PSS.PublicKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(publicKey, SecKeyRef::release)
    private val verifier = RsaPssSignatureVerifier(publicKey, algorithm)
    override fun signatureVerifier(): SignatureVerifier = verifier

    override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier {
        error("custom saltLength is not supported")
    }

    @OptIn(UnsafeNumber::class)
    override fun encodeToBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.PEM_RSA -> PEM.encodeToByteArray(PemContent(PemLabel.RsaPublicKey, encodeToPss()))
        RSA.PublicKey.Format.DER_RSA -> encodeToPss()
    }

    private fun encodeToPss(): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(publicKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey.toByteArray()
    }
}

private class RsaPssPrivateKey(
    private val privateKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.PSS.PrivateKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(privateKey, SecKeyRef::release)
    private val generator = RsaPssSignatureGenerator(privateKey, algorithm)

    override fun signatureGenerator(): SignatureGenerator = generator

    override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator {
        error("custom saltLength is not supported")
    }

    override fun encodeToBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.PEM_RSA -> PEM.encodeToByteArray(PemContent(PemLabel.RsaPrivateKey, encodeToPss()))
        RSA.PrivateKey.Format.DER_RSA -> encodeToPss()
    }

    private fun encodeToPss(): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(privateKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey.toByteArray()
    }
}

private class RsaPssSignatureGenerator(
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

private class RsaPssSignatureVerifier(
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


