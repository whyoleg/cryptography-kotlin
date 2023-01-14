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
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = useCryptor { cryptorRef, dataOutMoved ->
        val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }

        cryptorRef.create(kCCEncrypt, iv.refTo(0))
        val ciphertextOutput = ByteArray(cryptorRef.outputLength(plaintextInput.size))

        var moved = cryptorRef.update(
            dataIn = plaintextInput.refTo(0),
            dataInLength = plaintextInput.size,
            dataOut = ciphertextOutput.refTo(0),
            dataOutAvailable = ciphertextOutput.size,
            dataOutMoved = dataOutMoved,
        )

        if (ciphertextOutput.size != moved) moved += cryptorRef.final(
            dataOut = ciphertextOutput.refTo(moved),
            dataOutAvailable = ciphertextOutput.size - moved,
            dataOutMoved = dataOutMoved,
        )
        iv + ciphertextOutput
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = useCryptor { cryptorRef, dataOutMoved ->
        cryptorRef.create(kCCDecrypt, ciphertextInput.refTo(0))

        val plaintextOutput = ByteArray(cryptorRef.outputLength(ciphertextInput.size - ivSizeBytes))

        var moved = cryptorRef.update(
            dataIn = ciphertextInput.refTo(ivSizeBytes),
            dataInLength = ciphertextInput.size - ivSizeBytes,
            dataOut = plaintextOutput.refTo(0),
            dataOutAvailable = plaintextOutput.size,
            dataOutMoved = dataOutMoved
        )

        if (plaintextOutput.size != moved) moved += cryptorRef.final(
            dataOut = plaintextOutput.refTo(moved),
            dataOutAvailable = plaintextOutput.size - moved,
            dataOutMoved = dataOutMoved
        )

        if (plaintextOutput.size == moved) {
            plaintextOutput
        } else {
            plaintextOutput.copyOf(moved)
        }
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput) }
    }

    private inline fun <T> useCryptor(
        block: MemScope.(
            cryptorRef: CCCryptorRefVar,
            dataOutMoved: size_tVar,
        ) -> T,
    ): T = memScoped {
        val cryptorRef = alloc<CCCryptorRefVar>()
        val dataOutMoved = alloc<size_tVar>()
        try {
            block(cryptorRef, dataOutMoved)
        } finally {
            CCCryptorRelease(cryptorRef.value)
        }
    }

    private fun CCCryptorRefVar.create(op: CCOperation, iv: CValuesRef<*>) {
        checkResult(
            CCCryptorCreate(
                op = op,
                alg = kCCAlgorithmAES,
                options = if (padding) kCCOptionPKCS7Padding else 0.convert(),
                key = key.refTo(0),
                keyLength = key.size.convert(),
                iv = iv,
                cryptorRef = ptr,
            )
        )
    }

    private fun CCCryptorRefVar.outputLength(inputLength: Int): Int {
        return CCCryptorGetOutputLength(
            cryptorRef = value,
            inputLength = inputLength.convert(),
            final = true
        ).convert()
    }

    private fun CCCryptorRefVar.update(
        dataIn: CValuesRef<*>,
        dataInLength: Int,
        dataOut: CValuesRef<*>,
        dataOutAvailable: Int,
        dataOutMoved: size_tVar,
    ): Int {
        checkResult(
            CCCryptorUpdate(
                cryptorRef = value,
                dataIn = dataIn,
                dataInLength = dataInLength.convert(),
                dataOut = dataOut,
                dataOutAvailable = dataOutAvailable.convert(),
                dataOutMoved = dataOutMoved.ptr
            )
        )
        return dataOutMoved.value.convert()
    }

    private fun CCCryptorRefVar.final(
        dataOut: CValuesRef<*>,
        dataOutAvailable: Int,
        dataOutMoved: size_tVar,
    ): Int {
        checkResult(
            CCCryptorFinal(
                cryptorRef = value,
                dataOut = dataOut,
                dataOutAvailable = dataOutAvailable.convert(),
                dataOutMoved = dataOutMoved.ptr
            )
        )
        return dataOutMoved.value.convert()
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
