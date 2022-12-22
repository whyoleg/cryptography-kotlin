package dev.whyoleg.cryptography.corecrypto.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.key.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.random.*

private const val ivSizeBytes = 16 //bytes for GCM

internal class AesCbcKeyGeneratorProvider(
    private val state: CoreCryptoState,
) : KeyGeneratorProvider<SymmetricKeyParameters, AES.CBC.Key>() {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(state, parameters.size.value.bits)
}

internal class AesCbcKeyGenerator(
    private val state: CoreCryptoState,
    private val keySizeBytes: Int,
) : KeyGenerator<AES.CBC.Key> {
    override fun generateKeyBlocking(): AES.CBC.Key {
        val key = ByteArray(keySizeBytes)
        if (
            CCRandomGenerateBytes(key.refTo(0), keySizeBytes.convert()) != kCCSuccess
        ) throw CryptographyException("CCRandomGenerateBytes failed")
        return AES.CBC.Key(
            AesCbcCipherProvider(state, key),
            NotSupportedProvider()
        )
    }

    override suspend fun generateKey(): AES.CBC.Key {
        return state.execute { generateKeyBlocking() }
    }
}

internal class AesCbcCipherProvider(
    private val state: CoreCryptoState,
    private val key: Buffer,
) : BoxCipherProvider<AES.CBC.CipherParameters, AES.CBC.Box>() {
    override fun provideOperation(parameters: AES.CBC.CipherParameters): BoxCipher<AES.CBC.Box> =
        AesCbcCipher(state, key, parameters.padding)
}

internal class AesCbcCipher(
    private val state: CoreCryptoState,
    private val key: Buffer,
    private val padding: Boolean,
) : BoxCipher<AES.CBC.Box> {

    override fun ciphertextSize(plaintextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun plaintextSize(ciphertextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun encryptBlocking(plaintextInput: Buffer): Buffer {
        val iv = ByteArray(ivSizeBytes).also { Random.nextBytes(it) }
        //TODO: padding
        val ciphertextOutput = ByteArray(plaintextInput.size)
        val result = CCCrypt(
            op = kCCEncrypt,
            alg = kCCAlgorithmAES,
            options = if (padding) kCCOptionPKCS7Padding else 0.convert(),
            key = key.refTo(0),
            keyLength = key.size.convert(),
            iv = iv.refTo(0),
            dataIn = plaintextInput.refTo(0),
            dataInLength = plaintextInput.size.convert(),
            dataOut = ciphertextOutput.refTo(ivSizeBytes),
            dataOutAvailable = (ciphertextOutput.size - ivSizeBytes).convert(),
            dataOutMoved = null
        )
        if (result != kCCSuccess) throw CryptographyException("CCCrypt failed with code $result")
        return iv + ciphertextOutput
    }

    override fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        return encryptBlocking(plaintextInput).copyInto(ciphertextOutput)
    }

    override fun encryptBoxBlocking(plaintextInput: Buffer): AES.CBC.Box {
        TODO("Not yet implemented")
    }

    override fun encryptBoxBlocking(plaintextInput: Buffer, boxOutput: AES.CBC.Box): AES.CBC.Box {
        TODO("Not yet implemented")
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer {
        //TODO: padding
        val plaintextOutput = ByteArray(ciphertextInput.size - ivSizeBytes)
        val result = CCCrypt(
            op = kCCDecrypt,
            alg = kCCAlgorithmAES,
            options = if (padding) kCCOptionPKCS7Padding else 0.convert(),
            key = key.refTo(0),
            keyLength = key.size.convert(),
            iv = ciphertextInput.refTo(0),
            dataIn = ciphertextInput.refTo(ivSizeBytes),
            dataInLength = (ciphertextInput.size - ivSizeBytes).convert(),
            dataOut = plaintextOutput.refTo(0),
            dataOutAvailable = plaintextOutput.size.convert(),
            dataOutMoved = null
        )
        if (result != kCCSuccess) throw CryptographyException("CCCrypt failed with code $result")
        return plaintextOutput
    }

    override fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        return decryptBlocking(ciphertextInput).copyInto(plaintextOutput)
    }

    override fun decryptBoxBlocking(boxInput: AES.CBC.Box): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptBoxBlocking(boxInput: AES.CBC.Box, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(): EncryptFunction {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(): DecryptFunction {
        TODO("Not yet implemented")
    }

    override suspend fun decryptBox(boxInput: AES.CBC.Box): Buffer {
        return state.execute { decryptBoxBlocking(boxInput) }
    }

    override suspend fun decryptBox(boxInput: AES.CBC.Box, plaintextOutput: Buffer): Buffer {
        return state.execute { decryptBoxBlocking(boxInput, plaintextOutput) }
    }

    override suspend fun encryptBox(plaintextInput: Buffer): AES.CBC.Box {
        return state.execute { encryptBoxBlocking(plaintextInput) }
    }

    override suspend fun encryptBox(plaintextInput: Buffer, boxOutput: AES.CBC.Box): AES.CBC.Box {
        return state.execute { encryptBoxBlocking(plaintextInput, boxOutput) }
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput) }
    }

    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput, plaintextOutput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput, ciphertextOutput) }
    }
}
