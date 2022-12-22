package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 12 //bytes for GCM

internal object AesGcmKeyGeneratorProvider : KeyGeneratorProvider<SymmetricKeyParameters, AES.GCM.Key>(ENGINE_ID) {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.GCM.Key> =
        AesGcmKeyGenerator(parameters.size.value.bits)
}

internal class AesGcmKeyGenerator(
    private val keySizeBits: Int,
) : KeyGenerator<AES.GCM.Key> {
    override suspend fun generateKey(): AES.GCM.Key {
        val key = WebCrypto.subtle.generateKey(
            AesGcmKeyAlgorithm {
                this.length = keySizeBits
            },
            //TODO?
            true,
            arrayOf("encrypt", "decrypt")
        ).await()
        return AES.GCM.Key(
            AesGcmCipherProvider(key),
            NotSupportedProvider(ENGINE_ID)
        )
    }

    override fun generateKeyBlocking(): AES.GCM.Key {
        TODO("Not yet implemented")
    }
}

internal class AesGcmCipherProvider(
    private val key: CryptoKey,
) : AeadCipherProvider<AES.GCM.CipherParameters>(ENGINE_ID) {
    override fun provideOperation(parameters: AES.GCM.CipherParameters): AeadCipher = AesGcmCipher(key, parameters.tagSize.bits)
}

internal class AesGcmCipher(
    private val key: CryptoKey,
    private val tagSizeBits: Int,
) : AeadCipher {
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
                this.iv = ciphertextInput.copyOfRange(0, ivSizeBytes)
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

    override fun decryptFunction(): AeadDecryptFunction {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(): AeadEncryptFunction {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }
}
