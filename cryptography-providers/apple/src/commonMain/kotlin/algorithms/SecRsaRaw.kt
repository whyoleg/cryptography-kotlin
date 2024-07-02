/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

internal object SecRsaRaw : SecRsa<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair>(), RSA.RAW {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = null

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.RAW.KeyPair = RsaRawKeyPair(
        publicKey = RsaRawPublicKey(publicKey),
        privateKey = RsaRawPrivateKey(privateKey),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.RAW.PublicKey = RsaRawPublicKey(key)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.RAW.PrivateKey = RsaRawPrivateKey(key)

    private class RsaRawKeyPair(
        override val publicKey: RSA.RAW.PublicKey,
        override val privateKey: RSA.RAW.PrivateKey,
    ) : RSA.RAW.KeyPair

    private class RsaRawPublicKey(
        publicKey: SecKeyRef,
    ) : RsaPublicKey(publicKey), RSA.RAW.PublicKey {
        override fun encryptor(): Encryptor = RsaRawEncryptor(publicKey)
    }

    private class RsaRawPrivateKey(
        privateKey: SecKeyRef,
    ) : RsaPrivateKey(privateKey), RSA.RAW.PrivateKey {
        override fun decryptor(): Decryptor = RsaRawDecryptor(privateKey)
    }
}

private class RsaRawEncryptor(
    private val publicKey: SecKeyRef,
) : Encryptor {
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        plaintextInput.useNSData { plaintext ->
            val ciphertext = SecKeyCreateEncryptedData(
                key = publicKey,
                algorithm = kSecKeyAlgorithmRSAEncryptionRaw,
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

private class RsaRawDecryptor(
    private val privateKey: SecKeyRef,
) : Decryptor {
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        ciphertextInput.useNSData { ciphertext ->
            val plaintext = SecKeyCreateDecryptedData(
                key = privateKey,
                algorithm = kSecKeyAlgorithmRSAEncryptionRaw,
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
