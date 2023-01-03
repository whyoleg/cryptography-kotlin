package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.random.*

internal class CCAesCbc(
    private val state: AppleState,
) : AES.CBC {
    private val keyDecoder = AesCbcKeyDecoder(state)
    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = keyDecoder

    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(state, keySize.value.bytes)
}

private class AesCbcKeyDecoder(
    private val state: AppleState,
) : KeyDecoder<AES.Key.Format, AES.CBC.Key> {
    override fun decodeFromBlocking(format: AES.Key.Format, input: Buffer): AES.CBC.Key {
        TODO("Not yet implemented")
    }

    override suspend fun decodeFrom(format: AES.Key.Format, input: Buffer): AES.CBC.Key {
        return state.execute { decodeFromBlocking(format, input) }
    }
}

private class AesCbcKeyGenerator(
    private val state: AppleState,
    private val keySizeBytes: Int,
) : KeyGenerator<AES.CBC.Key> {
    override fun generateKeyBlocking(): AES.CBC.Key {
        val key = randomBytes(keySizeBytes)
        return wrapKey(state, key)
    }

    override suspend fun generateKey(): AES.CBC.Key {
        return state.execute { generateKeyBlocking() }
    }
}

private fun wrapKey(state: AppleState, key: ByteArray): AES.CBC.Key = object : AES.CBC.Key {
    override fun cipher(padding: Boolean): Cipher = AesCbcCipher(state, key, padding)

    override suspend fun encodeTo(format: AES.Key.Format): Buffer {
        TODO("Not yet implemented")
    }

    override fun encodeToBlocking(format: AES.Key.Format): Buffer {
        TODO("Not yet implemented")
    }
}

private const val ivSizeBytes = 16 //bytes for GCM

private class AesCbcCipher(
    private val state: AppleState,
    private val key: Buffer,
    private val padding: Boolean,
) : Cipher {

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

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput) }
    }

}
