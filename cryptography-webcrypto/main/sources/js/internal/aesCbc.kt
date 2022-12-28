package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 16 //bytes for CBC

internal object AesCbcKeyGeneratorProvider : KeyGeneratorProvider<SymmetricKeyParameters, AES.CBC.Key>() {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(parameters.size.value.bits)
}

internal class AesCbcKeyGenerator(
    keySizeBits: Int,
) : WebCryptoSymmetricKeyGenerator<AES.CBC.Key>(
    AesKeyGenerationAlgorithm("AES-CBC", keySizeBits),
    arrayOf("encrypt", "decrypt")
) {
    override fun wrap(key: CryptoKey): AES.CBC.Key {
        return AES.CBC.Key(
            AesCbcCipherProvider(key),
            NotSupportedProvider()
        )
    }
}

internal class AesCbcCipherProvider(
    private val key: CryptoKey,
) : BoxCipherProvider<AES.CBC.CipherParameters, AES.CBC.Box>() {
    override fun provideOperation(parameters: AES.CBC.CipherParameters): BoxCipher<AES.CBC.Box> {
        require(parameters.padding) { "NoPadding is not supported" }
        return AesCbcCipher(key)
    }
}

internal class AesCbcCipher(
    private val key: CryptoKey,
) : BoxCipher<AES.CBC.Box> {
    //todo
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes //+ tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes //- tagSizeBits / 8

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        val iv = WebCryptoRandom.random(ivSizeBytes)

        val result = WebCrypto.subtle.encrypt(
            AesCbcParams {
                this.iv = iv
            },
            key,
            plaintextInput
        ).await()

        return iv + result.toByteArray()
    }

    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        //TODO: check if correct
        encrypt(plaintextInput).copyInto(ciphertextOutput)
        return ciphertextOutput
    }

    override suspend fun encryptBox(plaintextInput: Buffer): AES.CBC.Box {
        TODO("Not yet implemented")
    }

    override suspend fun encryptBox(plaintextInput: Buffer, boxOutput: AES.CBC.Box): AES.CBC.Box {
        TODO("Not yet implemented")
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        val result = WebCrypto.subtle.decrypt(
            AesCbcParams {
                this.iv = ciphertextInput.copyOfRange(0, ivSizeBytes)
            },
            key,
            ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        ).await()

        return result.toByteArray()
    }

    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        decrypt(ciphertextInput).copyInto(plaintextOutput)
        return plaintextOutput
    }

    override suspend fun decryptBox(boxInput: AES.CBC.Box): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun decryptBox(boxInput: AES.CBC.Box, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = nonBlocking()
    override fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer = nonBlocking()
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = nonBlocking()
    override fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = nonBlocking()
    override fun decryptBoxBlocking(boxInput: AES.CBC.Box): Buffer = nonBlocking()
    override fun decryptBoxBlocking(boxInput: AES.CBC.Box, plaintextOutput: Buffer): Buffer = nonBlocking()
    override fun encryptBoxBlocking(plaintextInput: Buffer): AES.CBC.Box = nonBlocking()
    override fun encryptBoxBlocking(plaintextInput: Buffer, boxOutput: AES.CBC.Box): AES.CBC.Box = nonBlocking()
}
