package dev.whyoleg.cryptography.corecrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.key.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import kotlin.random.*

private const val ivSizeBytes = 16 //bytes for GCM

internal fun aesCbc(): AES.CBC {}

internal object AesCbc : AES.CBC() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> =
        AesCbcKeyGenerator(parameters.size.value.bytes)

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }
}

internal class AesCbcKeyGenerator(
    private val keySizeBytes: Int,
) : SyncKeyGenerator<AES.CBC.Key> {
    override fun generateKey(): AES.CBC.Key {
        val key = ByteArray(keySizeBytes)
        if (
            CCRandomGenerateBytes(key.refTo(0), keySizeBytes.convert()) != kCCSuccess
        ) throw CryptographyException("CCRandomGenerateBytes failed")
        return AesCbcKey(key)
    }
}

internal class AesCbcKey(
    private val key: Buffer,
) : AES.CBC.Key() {
    override fun syncCipher(parameters: AES.CBC.CipherParameters): SyncCipher = AesCbcCipher(parameters.padding, key)

    override fun asyncCipher(parameters: AES.CBC.CipherParameters): AsyncCipher {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(parameters: AES.CBC.CipherParameters): EncryptFunction {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(parameters: AES.CBC.CipherParameters): DecryptFunction {
        TODO("Not yet implemented")
    }
}

internal class AesCbcCipher(
    private val padding: Boolean,
    private val key: Buffer,
) : SyncCipher {

    override fun ciphertextSize(plaintextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun plaintextSize(ciphertextSize: Int): Int {
        TODO("Not yet implemented")
    }

    override fun encrypt(plaintextInput: Buffer): Buffer {
        val iv = ByteArray(ivSizeBytes).also { Random.nextBytes(it) }
        //TODO: padding
        val ciphertextOutput = ByteArray(plaintextInput.size)
        val result = CCCrypt(
            kCCEncrypt,
            kCCAlgorithmAES,
            if (padding) kCCOptionPKCS7Padding else 0.convert(),
            key.refTo(0),
            key.size.convert(),
            iv.refTo(0),
            plaintextInput.refTo(0),
            plaintextInput.size.convert(),
            ciphertextOutput.refTo(ivSizeBytes),
            (ciphertextOutput.size - ivSizeBytes).convert(),
            null
        )
        if (result != kCCSuccess) throw CryptographyException("CCCrypt failed with code $result")
        return iv + ciphertextOutput
    }

    override fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        return encrypt(plaintextInput).copyInto(ciphertextOutput)
    }

    override fun decrypt(ciphertextInput: Buffer): Buffer {
        //TODO: padding
        val plaintextOutput = ByteArray(ciphertextInput.size - ivSizeBytes)
        val result = CCCrypt(
            kCCDecrypt,
            kCCAlgorithmAES,
            if (padding) kCCOptionPKCS7Padding else 0.convert(),
            key.refTo(0),
            key.size.convert(),
            ciphertextInput.refTo(0),
            ciphertextInput.refTo(ivSizeBytes),
            (ciphertextInput.size - ivSizeBytes).convert(),
            plaintextOutput.refTo(0),
            plaintextOutput.size.convert(),
            null
        )
        if (result != kCCSuccess) throw CryptographyException("CCCrypt failed with code $result")
        return plaintextOutput
    }

    override fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        return decrypt(ciphertextInput).copyInto(plaintextOutput)
    }

}
