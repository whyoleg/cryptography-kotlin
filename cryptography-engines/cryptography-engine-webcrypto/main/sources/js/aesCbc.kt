package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.webcrypto.external.*

private const val ivSizeBytes = 16 //bytes for CBC

internal object AesCbcKeyGeneratorProvider : KeyGeneratorProvider<SymmetricKeyParameters, AES.CBC.Key>(ENGINE_ID) {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(parameters.size.value.bits)
}

internal class AesCbcKeyGenerator(
    private val keySizeBits: Int,
) : KeyGenerator<AES.CBC.Key> {
    override suspend fun generateKey(): AES.CBC.Key {
        val key = WebCrypto.subtle.generateKey(
            AesCbcKeyAlgorithm {
                this.length = keySizeBits
            },
            //TODO?
            true,
            arrayOf("encrypt", "decrypt")
        ).await()
        return AES.CBC.Key(
            AesCbcCipherProvider(key),
            NotSupportedProvider(ENGINE_ID)
        )
    }

    override fun generateKeyBlocking(): AES.CBC.Key {
        TODO("Not yet implemented")
    }
}

internal class AesCbcCipherProvider(
    private val key: CryptoKey,
) : CipherProvider<AES.CBC.CipherParameters>(ENGINE_ID) {
    override fun provideOperation(parameters: AES.CBC.CipherParameters): Cipher {
        require(parameters.padding) { "NoPadding is not supported" }
        return AesCbcCipher(key)
    }
}

internal class AesCbcCipher(
    private val key: CryptoKey,
) : Cipher {
    //todo
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes //+ tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes //- tagSizeBits / 8

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
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

    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        //TODO: check if correct
        encrypt(plaintextInput).copyInto(ciphertextOutput)
        return ciphertextOutput
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

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(): DecryptFunction {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(plaintextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(): EncryptFunction {
        TODO("Not yet implemented")
    }
}
