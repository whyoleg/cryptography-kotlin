package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.cipher.aead.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 16 //bytes for CBC

internal object AesCbc : AES.CBC() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> =
        AesCbcKeyGenerator(parameters.size.value.bits)
}

internal class AesCbcKeyGenerator(
    private val keySizeBits: Int,
) : AsyncKeyGenerator<AES.CBC.Key> {
    override suspend fun generateKey(): AES.CBC.Key {
        val result = WebCrypto.subtle.generateKey(
            AesCbcKeyAlgorithm {
                this.length = keySizeBits
            },
            //TODO?
            true,
            arrayOf("encrypt", "decrypt")
        ).await()
        return AesCbcKey(result)
    }
}

internal class AesCbcKey(
    private val key: CryptoKey,
) : AES.CBC.Key() {
    override fun syncCipher(parameters: AES.CBC.CipherParameters): SyncCipher {
        TODO("Not yet implemented")
    }

    override fun asyncCipher(parameters: AES.CBC.CipherParameters): AsyncCipher {
        require(parameters.padding) { "NoPadding is not supported" }
        return AesCbcCipher(key)
    }

    override fun decryptFunction(parameters: AES.CBC.CipherParameters): DecryptFunction {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(parameters: AES.CBC.CipherParameters): EncryptFunction {
        TODO("Not yet implemented")
    }
}

internal class AesCbcCipher(
    private val key: CryptoKey,
) : AeadAsyncCipher {
    //todo
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes //+ tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes //- tagSizeBits / 8

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        val iv = WebCrypto.getRandomValues(ByteArray(ivSizeBytes))

        val result = WebCrypto.subtle.encrypt(
            AesCbcParams {
                this.iv = iv
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
            AesCbcParams {
                this.iv = ciphertextInput.copyOfRange(0, ivSizeBytes)
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
