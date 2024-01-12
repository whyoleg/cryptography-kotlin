/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.random.*

internal object WebCryptoAesGcm : AES.GCM {
    private val keyUsages = arrayOf("encrypt", "decrypt")
    private val keyFormat: (AES.Key.Format) -> String = {
        when (it) {
            AES.Key.Format.RAW -> "raw"
            AES.Key.Format.JWK -> "jwk"
        }
    }
    private val wrapKey: (CryptoKey) -> AES.GCM.Key = { key ->
        object : AES.GCM.Key, EncodableKey<AES.Key.Format> by WebCryptoEncodableKey(key, keyFormat) {
            override fun cipher(tagSize: BinarySize): AuthenticatedCipher = AesGcmCipher(key, tagSize.inBits)
        }
    }
    private val keyDecoder = WebCryptoKeyDecoder(Algorithm("AES-GCM"), keyUsages, keyFormat, wrapKey)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.GCM.Key> = keyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.GCM.Key> =
        WebCryptoSymmetricKeyGenerator(AesKeyGenerationAlgorithm("AES-GCM", keySize.value.inBits), keyUsages, wrapKey)
}

private const val ivSizeBytes = 12 //bytes for GCM

private class AesGcmCipher(
    private val key: CryptoKey,
    private val tagSizeBits: Int,
) : AuthenticatedCipher {

    override suspend fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)

        val ciphertext = WebCrypto.encrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = iv,
                tagLength = tagSizeBits
            ),
            key = key,
            data = plaintextInput
        )

        return iv + ciphertext
    }

    override suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = ciphertextInput.copyOfRange(0, ivSizeBytes),
                tagLength = tagSizeBits
            ),
            key = key,
            data = ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
