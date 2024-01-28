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

internal object SecRsaPkcs1 : RSA.PKCS1 {
    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PKCS1.PublicKey> =
        RsaPkcs1PublicKeyDecoder(digest.rsaPkcs1SecKeyAlgorithm())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PKCS1.PrivateKey> =
        RsaPkcs1PrivateKeyDecoder(digest.rsaPkcs1SecKeyAlgorithm())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.PKCS1.KeyPair> {
        check(publicExponent == 65537.toBigInt()) { "Only F4 public exponent is supported" }

        return RsaPkcs1KeyPairGenerator(keySize.inBits, digest.rsaPkcs1SecKeyAlgorithm())
    }
}

private class RsaPkcs1PublicKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PublicKey.Format, RSA.PKCS1.PublicKey> {
    override fun decodeFromBlocking(format: RSA.PublicKey.Format, input: ByteArray): RSA.PKCS1.PublicKey = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.DER_RSA -> input.useNSData(::decodeFromPkcs1)
        RSA.PublicKey.Format.PEM_RSA -> PEM.decode(input).ensurePemLabel(PemLabel.RsaPublicKey).bytes.useNSData(::decodeFromPkcs1)
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPkcs1(input: NSData): RSA.PKCS1.PublicKey = memScoped {
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

            RsaPkcs1PublicKey(publicKey, algorithm)
        }
    }
}

private class RsaPkcs1PrivateKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PrivateKey.Format, RSA.PKCS1.PrivateKey> {
    override fun decodeFromBlocking(format: RSA.PrivateKey.Format, input: ByteArray): RSA.PKCS1.PrivateKey = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.DER_RSA -> input.useNSData(::decodeFromPkcs1)
        RSA.PrivateKey.Format.PEM_RSA -> PEM.decode(input).ensurePemLabel(PemLabel.RsaPrivateKey).bytes.useNSData(::decodeFromPkcs1)
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromPkcs1(input: NSData): RSA.PKCS1.PrivateKey = memScoped {
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

            RsaPkcs1PrivateKey(privateKey, algorithm)
        }
    }
}

private class RsaPkcs1KeyPairGenerator(
    private val keySizeBits: Int,
    private val algorithm: SecKeyAlgorithm?,
) : KeyGenerator<RSA.PKCS1.KeyPair> {

    @OptIn(UnsafeNumber::class)
    override fun generateKeyBlocking(): RSA.PKCS1.KeyPair = memScoped {
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

            RsaPkcs1KeyPair(
                RsaPkcs1PublicKey(publicKey!!, algorithm),
                RsaPkcs1PrivateKey(privateKey, algorithm)
            )
        }
    }
}

private class RsaPkcs1KeyPair(
    override val publicKey: RSA.PKCS1.PublicKey,
    override val privateKey: RSA.PKCS1.PrivateKey,
) : RSA.PKCS1.KeyPair

private class RsaPkcs1PublicKey(
    private val publicKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.PKCS1.PublicKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(publicKey, SecKeyRef::release)
    private val verifier = RsaPkcs1SignatureVerifier(publicKey, algorithm)
    override fun signatureVerifier(): SignatureVerifier = verifier

    @OptIn(UnsafeNumber::class)
    override fun encodeToBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.PEM_RSA -> PEM.encodeToByteArray(PemContent(PemLabel.RsaPublicKey, encodeToPkcs1()))
        RSA.PublicKey.Format.DER_RSA -> encodeToPkcs1()
    }

    private fun encodeToPkcs1(): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(publicKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey.toByteArray()
    }
}

private class RsaPkcs1PrivateKey(
    private val privateKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.PKCS1.PrivateKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(privateKey, SecKeyRef::release)
    private val generator = RsaPkcs1SignatureGenerator(privateKey, algorithm)

    override fun signatureGenerator(): SignatureGenerator = generator

    override fun encodeToBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.PEM_RSA -> PEM.encodeToByteArray(PemContent(PemLabel.RsaPrivateKey, encodeToPkcs1()))
        RSA.PrivateKey.Format.DER_RSA -> encodeToPkcs1()
    }

    private fun encodeToPkcs1(): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(privateKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey.toByteArray()
    }
}

private class RsaPkcs1SignatureGenerator(
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

private class RsaPkcs1SignatureVerifier(
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
