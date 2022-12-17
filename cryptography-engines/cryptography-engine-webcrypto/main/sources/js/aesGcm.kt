package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.cipher.aead.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 12 //bytes for GCM

internal object AesGcm : AES.GCM() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> =
        AesGcmKeyGenerator(parameters.size.value.bits)
}

internal class AesGcmKeyGenerator(
    private val keySizeBits: Int,
) : AsyncKeyGenerator<AES.GCM.Key> {
    override suspend fun generateKey(): AES.GCM.Key {
        val result = WebCrypto.subtle.generateKey(
            AesGcmKeyAlgorithm {
                this.length = keySizeBits
            },
            //TODO?
            true,
            arrayOf("encrypt", "decrypt")
        ).await()
        return AesGcmKey(result)
    }
}

internal class AesGcmKey(
    private val key: CryptoKey,
) : AES.GCM.Key() {
    override fun syncCipher(parameters: AES.GCM.CipherParameters): SyncCipher {
        TODO("Not yet implemented")
    }

    override fun asyncCipher(parameters: AES.GCM.CipherParameters): AsyncCipher = AesGcmCipher(parameters.tagSize.bits, key)

    override fun decryptFunction(parameters: AES.GCM.CipherParameters): DecryptFunction {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(parameters: AES.GCM.CipherParameters): EncryptFunction {
        TODO("Not yet implemented")
    }
}

internal class AesGcmCipher(
    private val tagSizeBits: Int,
    private val key: CryptoKey,
) : AeadAsyncCipher {
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes + tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes - tagSizeBits / 8

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        val iv = WebCrypto.getRandomValues(ByteArray(ivSizeBytes))

        val result = WebCrypto.subtle.encrypt(
            AesGcmParams {
                this.iv = iv
                this.additionalData = associatedData
                this.tagLength = tagSizeBits
            },
            key,
            plaintextInput
        ).await()

        return iv + result.toByteArray()
    }

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        //TODO: check if correct
        encrypt(associatedData, plaintextInput).copyInto(ciphertextOutput)
        return ciphertextOutput
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        val result = WebCrypto.subtle.decrypt(
            AesGcmParams {
                this.iv = iv.copyOfRange(0, ivSizeBytes)
                this.additionalData = associatedData
                this.tagLength = tagSizeBits
            },
            key,
            ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        ).await()

        return result.toByteArray()
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        decrypt(associatedData, ciphertextInput).copyInto(plaintextOutput)
        return plaintextOutput
    }
}
