/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal object SecRsaOaep : SecRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(), RSA.OAEP {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaOaepSecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.OAEP.KeyPair = RsaOaepKeyPair(
        publicKey = RsaOaepPublicKey(publicKey, algorithm),
        privateKey = RsaOaepPrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.OAEP.PublicKey = RsaOaepPublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.OAEP.PrivateKey = RsaOaepPrivateKey(key, algorithm)

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(
        publicKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.OAEP.PublicKey {
        private val encryptor = RsaOaepEncryptor(publicKey, algorithm)
        override fun encryptor(): AuthenticatedEncryptor = encryptor
    }

    private class RsaOaepPrivateKey(
        privateKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.OAEP.PrivateKey {
        private val decryptor = RsaOaepDecryptor(privateKey, algorithm)
        override fun decryptor(): AuthenticatedDecryptor = decryptor
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
