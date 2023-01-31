package dev.whyoleg.cryptography.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.materials.*

private const val ivSizeBytes = 16 //bytes for CBC

internal object WebCryptoAesCbc : AES.CBC {
    private val keyUsages = arrayOf("encrypt", "decrypt")
    private val keyFormat: (AES.Key.Format) -> String = {
        when (it) {
            AES.Key.Format.RAW -> "raw"
            AES.Key.Format.JWK -> "jwk"
        }
    }
    private val wrapKey: (CryptoKey) -> AES.CBC.Key = { key ->
        object : AES.CBC.Key, EncodableKey<AES.Key.Format> by WebCryptoEncodableKey(key, keyFormat) {
            override fun cipher(padding: Boolean): Cipher {
                require(padding) { "Padding is required in WebCrypto" }
                return AesCbcCipher(key)
            }
        }
    }
    private val keyDecoder = WebCryptoKeyDecoder(Algorithm("AES-CBC"), keyUsages, keyFormat, wrapKey)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = keyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> =
        WebCryptoSymmetricKeyGenerator(AesKeyGenerationAlgorithm("AES-CBC", keySize.value.inBits), keyUsages, wrapKey)
}

private class AesCbcCipher(private val key: CryptoKey) : Cipher {

    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)

        val result = WebCrypto.subtle.encrypt(
            AesCbcParams(iv),
            key,
            plaintextInput
        ).await()

        return iv + result.toByteArray()
    }

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray {
        val result = WebCrypto.subtle.decrypt(
            AesCbcParams(ciphertextInput.copyOfRange(0, ivSizeBytes)),
            key,
            ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        ).await()

        return result.toByteArray()
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = nonBlocking()
}
