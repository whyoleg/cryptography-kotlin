/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object SecRsaOaep : RSA.OAEP {
    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> =
        RsaOaepPublicKeyDecoder(digest.rsaOaepSecKeyAlgorithm())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        RsaOaepPrivateKeyDecoder(digest.rsaOaepSecKeyAlgorithm())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.OAEP.KeyPair> {
        check(publicExponent == RSA.PublicExponent.F4) { "Only F4 public exponent is supported" }

        return RsaOaepKeyPairGenerator(keySize.inBits, digest.rsaOaepSecKeyAlgorithm())
    }
}

private class RsaOaepPublicKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> {
    override fun decodeFromBlocking(format: RSA.PublicKey.Format, input: ByteArray): RSA.OAEP.PublicKey = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.DER_RSA -> input.useNSData { decodeFromOaep(it) }
        RSA.PublicKey.Format.PEM_RSA -> decodeFromOaep(input.decodeFromPem("RSA PUBLIC KEY") ?: error("Can't decode public key"))
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromOaep(input: NSData): RSA.OAEP.PublicKey = memScoped {
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

            RsaOaepPublicKey(publicKey, algorithm)
        }
    }
}

private class RsaOaepPrivateKeyDecoder(
    private val algorithm: SecKeyAlgorithm?,
) : KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> {
    override fun decodeFromBlocking(format: RSA.PrivateKey.Format, input: ByteArray): RSA.OAEP.PrivateKey = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.DER_RSA -> input.useNSData { decodeFromOaep(it) }
        RSA.PrivateKey.Format.PEM_RSA -> decodeFromOaep(input.decodeFromPem("RSA PRIVATE KEY") ?: error("Can't decode private key"))
    }

    @OptIn(UnsafeNumber::class)
    private fun decodeFromOaep(input: NSData): RSA.OAEP.PrivateKey = memScoped {
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

            RsaOaepPrivateKey(privateKey, algorithm)
        }
    }
}

private class RsaOaepKeyPairGenerator(
    private val keySizeBits: Int,
    private val algorithm: SecKeyAlgorithm?,
) : KeyGenerator<RSA.OAEP.KeyPair> {

    @OptIn(UnsafeNumber::class)
    override fun generateKeyBlocking(): RSA.OAEP.KeyPair = memScoped {
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

            RsaOaepKeyPair(
                RsaOaepPublicKey(publicKey!!, algorithm),
                RsaOaepPrivateKey(privateKey, algorithm)
            )
        }
    }
}

private class RsaOaepKeyPair(
    override val publicKey: RSA.OAEP.PublicKey,
    override val privateKey: RSA.OAEP.PrivateKey,
) : RSA.OAEP.KeyPair

private class RsaOaepPublicKey(
    private val publicKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.OAEP.PublicKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(publicKey, SecKeyRef::release)
    private val encryptor = RsaOaepEncryptor(publicKey, algorithm)

    override fun encryptor(): AuthenticatedEncryptor = encryptor

    @OptIn(UnsafeNumber::class)
    override fun encodeToBlocking(format: RSA.PublicKey.Format): ByteArray = when (format) {
        RSA.PublicKey.Format.DER     -> TODO()
        RSA.PublicKey.Format.PEM     -> TODO()
        RSA.PublicKey.Format.JWK     -> TODO()
        RSA.PublicKey.Format.PEM_RSA -> encodeToOaep().encodeToPem("RSA PUBLIC KEY")
        RSA.PublicKey.Format.DER_RSA -> encodeToOaep().toByteArray()
    }

    private fun encodeToOaep(): NSData = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(publicKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey
    }
}

private class RsaOaepPrivateKey(
    private val privateKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
) : RSA.OAEP.PrivateKey {
    @OptIn(ExperimentalNativeApi::class)
    private val cleanup = createCleaner(privateKey, SecKeyRef::release)
    private val decryptor = RsaOaepDecryptor(privateKey, algorithm)
    override fun decryptor(): AuthenticatedDecryptor = decryptor

    override fun encodeToBlocking(format: RSA.PrivateKey.Format): ByteArray = when (format) {
        RSA.PrivateKey.Format.DER     -> TODO()
        RSA.PrivateKey.Format.PEM     -> TODO()
        RSA.PrivateKey.Format.JWK     -> TODO()
        RSA.PrivateKey.Format.PEM_RSA -> encodeToOaep().encodeToPem("RSA PRIVATE KEY")
        RSA.PrivateKey.Format.DER_RSA -> encodeToOaep().toByteArray()
    }

    private fun encodeToOaep(): NSData = memScoped {
        val error = alloc<CFErrorRefVar>()
        val encodedKey = SecKeyCopyExternalRepresentation(privateKey, error.ptr)?.releaseBridgeAs<NSData>()
        if (encodedKey == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encode key: ${nsError?.description}")
        }
        encodedKey
    }
}

private class RsaOaepEncryptor(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : AuthenticatedEncryptor {
    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        require(associatedData == null) { "Associated data inclusion is not supported" }

        return memScoped {
            val error = alloc<CFErrorRefVar>()
            plaintextInput.useNSData { plaintext ->
                val ciphertext = SecKeyCreateEncryptedData(
                    key = publicKey,
                    algorithm = algorithm,
                    plaintext = plaintext.retainBridgeAs<CFDataRef>(),
                    error = error.ptr
                )?.releaseBridgeAs<NSData>()

                if (ciphertext == null) {
                    val nsError = error.value.releaseBridgeAs<NSError>()
                    error("Failed to encrypt: ${nsError?.description}")
                }

                ciphertext.toByteArray()
            }
        }
    }
}

private class RsaOaepDecryptor(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : AuthenticatedDecryptor {
    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        require(associatedData == null) { "Associated data inclusion is not supported" }

        return memScoped {
            val error = alloc<CFErrorRefVar>()
            ciphertextInput.useNSData { ciphertext ->
                // TODO: may be there could be an issue with retain/release?
                val plaintext = SecKeyCreateDecryptedData(
                    key = privateKey,
                    algorithm = algorithm,
                    ciphertext = ciphertext.retainBridgeAs<CFDataRef>(),
                    error = error.ptr
                )?.releaseBridgeAs<NSData>()

                if (plaintext == null) {
                    val nsError = error.value.releaseBridgeAs<NSError>()
                    error("Failed to decrypt: ${nsError?.description}")
                }

                plaintext.toByteArray()
            }
        }
    }
}
