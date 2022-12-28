package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 12 //bytes for GCM

internal object AesGcmKeyGeneratorProvider : KeyGeneratorProvider<SymmetricKeyParameters, AES.GCM.Key>() {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.GCM.Key> =
        AesGcmKeyGenerator(parameters.size.value.bits)
}

internal class AesGcmKeyGenerator(
    keySizeBits: Int,
) : WebCryptoSymmetricKeyGenerator<AES.GCM.Key>(
    AesKeyGenerationAlgorithm("AES-GCM", keySizeBits),
    arrayOf("encrypt", "decrypt")
) {
    override fun wrap(key: CryptoKey): AES.GCM.Key {
        return AES.GCM.Key(
            AesGcmCipherProvider(key),
            NotSupportedProvider()
        )
    }
}

internal class AesGcmCipherProvider(
    private val key: CryptoKey,
) : AeadBoxCipherProvider<AES.GCM.CipherParameters, AES.GCM.Box>() {
    override fun provideOperation(parameters: AES.GCM.CipherParameters): AeadBoxCipher<AES.GCM.Box> =
        AesGcmCipher(key, parameters.tagSize.bits)
}

internal class AesGcmCipher(
    private val key: CryptoKey,
    private val tagSizeBits: Int,
) : AeadBoxCipher<AES.GCM.Box> {
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes + tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes - tagSizeBits / 8

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        val iv = WebCryptoRandom.random(ivSizeBytes)

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

    override suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer): AES.GCM.Box {
        TODO("Not yet implemented")
    }

    override suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: AES.GCM.Box): AES.GCM.Box {
        TODO("Not yet implemented")
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

    override suspend fun decryptBox(associatedData: Buffer?, boxInput: AES.GCM.Box): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun decryptBox(associatedData: Buffer?, boxInput: AES.GCM.Box, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer = nonBlocking()
    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = nonBlocking()
    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer = nonBlocking()
    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = nonBlocking()
    override fun decryptBoxBlocking(associatedData: Buffer?, boxInput: AES.GCM.Box): Buffer = nonBlocking()
    override fun decryptBoxBlocking(associatedData: Buffer?, boxInput: AES.GCM.Box, plaintextOutput: Buffer): Buffer = nonBlocking()
    override fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer): AES.GCM.Box = nonBlocking()
    override fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: AES.GCM.Box): AES.GCM.Box = nonBlocking()
}
