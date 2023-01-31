package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*

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

        val ciphertext = WebCrypto.subtle.encrypt(
            AesGcmParams(additionalData = associatedData, iv = iv, tagLength = tagSizeBits),
            key,
            plaintextInput
        ).await()

        return iv + ciphertext.toByteArray()
    }

    override suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        val plaintext = WebCrypto.subtle.decrypt(
            AesGcmParams(additionalData = associatedData, iv = ciphertextInput.copyOfRange(0, ivSizeBytes), tagLength = tagSizeBits),
            key,
            ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        ).await()

        return plaintext.toByteArray()
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
