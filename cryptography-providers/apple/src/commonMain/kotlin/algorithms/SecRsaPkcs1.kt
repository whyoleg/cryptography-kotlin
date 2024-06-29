/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal object SecRsaPkcs1 : SecRsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(), RSA.PKCS1 {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPkcs1SecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.PKCS1.KeyPair = RsaPkcs1KeyPair(
        publicKey = RsaPkcs1PublicKey(publicKey, algorithm),
        privateKey = RsaPkcs1PrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PKCS1.PublicKey = RsaPkcs1PublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PKCS1.PrivateKey = RsaPkcs1PrivateKey(key, algorithm)

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        publicKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = RsaPkcs1SignatureVerifier(publicKey, algorithm)
        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(publicKey)
    }

    private class RsaPkcs1PrivateKey(
        privateKey: SecKeyRef,
        private val algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = RsaPkcs1SignatureGenerator(privateKey, algorithm)
        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(privateKey)
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

private class RsaPkcs1Encryptor(
    private val publicKey: SecKeyRef,
) : Encryptor {
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        plaintextInput.useNSData { plaintext ->
            val ciphertext = SecKeyCreateEncryptedData(
                key = publicKey,
                algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1,
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

private class RsaPkcs1Decryptor(
    private val privateKey: SecKeyRef,
) : Decryptor {
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        ciphertextInput.useNSData { ciphertext ->
            val plaintext = SecKeyCreateDecryptedData(
                key = privateKey,
                algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1,
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
