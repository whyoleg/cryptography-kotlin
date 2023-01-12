package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.posix.*

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
        if (format == AES.Key.Format.RAW) return wrapKey(state, input)
        TODO("$format is not yet supported")
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
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(state, key)
    }

    override suspend fun generateKey(): AES.CBC.Key {
        return state.execute { generateKeyBlocking() }
    }
}

private fun wrapKey(state: AppleState, key: ByteArray): AES.CBC.Key = object : AES.CBC.Key {
    override fun cipher(padding: Boolean): Cipher = AesCbcCipher(state, key, padding)

    override fun encodeToBlocking(format: AES.Key.Format): Buffer {
        if (format == AES.Key.Format.RAW) return key
        TODO("$format is not yet supported")
    }

    override suspend fun encodeTo(format: AES.Key.Format): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

private const val ivSizeBytes = 16 //bytes for GCM

private class AesCbcCipher(
    private val state: AppleState,
    private val key: Buffer,
    private val padding: Boolean,
) : Cipher {

    override fun encryptBlocking(plaintextInput: Buffer): Buffer = memScoped {
        val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }
        val cryptorRef = alloc<CCCryptorRefVar>()

        checkResult(
            CCCryptorCreate(
                op = kCCEncrypt,
                alg = kCCAlgorithmAES,
                options = if (padding) kCCOptionPKCS7Padding else 0.convert(),
                key = key.refTo(0),
                keyLength = key.size.convert(),
                iv = iv.refTo(0),
                cryptorRef = cryptorRef.ptr,
            )
        )

        val ciphertextSize = CCCryptorGetOutputLength(
            cryptorRef = cryptorRef.value,
            inputLength = plaintextInput.size.convert(),
            final = true
        ).toInt()
        val ciphertextOutput = ByteArray(ciphertextSize)

        val dataOutMoved = alloc<size_tVar>()
        checkResult(
            CCCryptorUpdate(
                cryptorRef = cryptorRef.value,
                dataIn = plaintextInput.refTo(0),
                dataInLength = plaintextInput.size.convert(),
                dataOut = ciphertextOutput.refTo(0),
                dataOutAvailable = ciphertextSize.convert(),
                dataOutMoved = dataOutMoved.ptr
            )
        )
        val moved = dataOutMoved.value.toInt()
        checkResult(
            CCCryptorFinal(
                cryptorRef = cryptorRef.value,
                dataOut = ciphertextOutput.refTo(moved),
                dataOutAvailable = (ciphertextSize - moved).convert(),
                dataOutMoved = null,
            )
        )
        val ciphertext = iv + ciphertextOutput
        ciphertext
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = memScoped {
        val cryptorRef = alloc<CCCryptorRefVar>()
        checkResult(
            CCCryptorCreate(
                op = kCCDecrypt,
                alg = kCCAlgorithmAES,
                options = if (padding) kCCOptionPKCS7Padding else 0.convert(),
                key = key.refTo(0),
                keyLength = key.size.convert(),
                iv = ciphertextInput.refTo(0),
                cryptorRef = cryptorRef.ptr,
            )
        )

        val plaintextSize = CCCryptorGetOutputLength(
            cryptorRef = cryptorRef.value,
            inputLength = (ciphertextInput.size - ivSizeBytes).convert(),
            final = true
        ).toInt()
        val plaintextOutput = ByteArray(plaintextSize)
        val dataOutMoved = alloc<size_tVar>()
        checkResult(
            CCCryptorUpdate(
                cryptorRef = cryptorRef.value,
                dataIn = ciphertextInput.refTo(ivSizeBytes),
                dataInLength = (ciphertextInput.size - ivSizeBytes).convert(),
                dataOut = plaintextOutput.refTo(0),
                dataOutAvailable = plaintextSize.convert(),
                dataOutMoved = dataOutMoved.ptr
            )
        )
        val moved = dataOutMoved.value.toInt()
        checkResult(
            CCCryptorFinal(
                cryptorRef = cryptorRef.value,
                dataOut = plaintextOutput.refTo(moved),
                dataOutAvailable = (plaintextSize - moved).convert(),
                dataOutMoved = dataOutMoved.ptr,
            )
        )
        val ptMoved = moved + dataOutMoved.value.toInt()
        plaintextOutput.copyOf(ptMoved)
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput) }
    }

    private fun checkResult(result: CCCryptorStatus) {
        when (result) {
            kCCSuccess        -> null
            kCCParamError     -> "Illegal parameter value."
            kCCBufferTooSmall -> "Insufficent buffer provided for specified operation."
            kCCMemoryFailure  -> "Memory allocation failure."
            kCCAlignmentError -> "Input size was not aligned properly."
            kCCDecodeError    -> "Input data did not decode or decrypt properly."
            kCCUnimplemented  -> "Function not implemented for the current algorithm."
            else              -> "CCCrypt failed with code $result"
        }?.let { throw CryptographyException(it) }
    }
}
