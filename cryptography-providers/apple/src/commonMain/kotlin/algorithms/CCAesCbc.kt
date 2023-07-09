/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.posix.*

internal object CCAesCbc : AES.CBC {
    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = AesCbcKeyDecoder

    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(keySize.value.inBytes)
}

private object AesCbcKeyDecoder : KeyDecoder<AES.Key.Format, AES.CBC.Key> {
    override fun decodeFromBlocking(format: AES.Key.Format, input: ByteArray): AES.CBC.Key = when (format) {
        AES.Key.Format.RAW -> {
            require(input.size == 16 || input.size == 24 || input.size == 32) {
                "AES key size must be 128, 192 or 256 bits"
            }
            wrapKey(input.copyOf())
        }
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class AesCbcKeyGenerator(
    private val keySizeBytes: Int,
) : KeyGenerator<AES.CBC.Key> {
    override fun generateKeyBlocking(): AES.CBC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(key)
    }
}

private fun wrapKey(key: ByteArray): AES.CBC.Key = object : AES.CBC.Key {
    override fun cipher(padding: Boolean): Cipher = AesCbcCipher(key, padding)

    override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.RAW -> key.copyOf()
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private const val ivSizeBytes = 16 //bytes for CBC
private const val blockSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(
    private val key: ByteArray,
    private val padding: Boolean,
) : Cipher {
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = useCryptor { cryptorRef, dataOutMoved ->
        val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }

        cryptorRef.create(kCCEncrypt, iv.refTo(0))
        val ciphertextOutput = ByteArray(cryptorRef.outputLength(plaintextInput.size))

        val moved = cryptorRef.update(
            dataIn = plaintextInput.fixEmpty().refTo(0),
            dataInLength = plaintextInput.size,
            dataOut = ciphertextOutput.fixEmpty().refTo(0),
            dataOutAvailable = ciphertextOutput.size,
            dataOutMoved = dataOutMoved,
        )

        if (ciphertextOutput.size != moved) cryptorRef.final(
            dataOut = ciphertextOutput.refTo(moved),
            dataOutAvailable = ciphertextOutput.size - moved,
            dataOutMoved = dataOutMoved,
        )
        iv + ciphertextOutput
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }
        require(ciphertextInput.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return useCryptor { cryptorRef, dataOutMoved ->
            cryptorRef.create(kCCDecrypt, ciphertextInput.refTo(0))

            val plaintextOutput = ByteArray(cryptorRef.outputLength(ciphertextInput.size - ivSizeBytes))

            var moved = cryptorRef.update(
                dataIn = ciphertextInput.refToFixed(ivSizeBytes),
                dataInLength = ciphertextInput.size - ivSizeBytes,
                dataOut = plaintextOutput.refToFixed(0),
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
        val error = when (result) {
            kCCSuccess        -> return
            kCCParamError     -> "Illegal parameter value."
            kCCBufferTooSmall -> "Insufficent buffer provided for specified operation."
            kCCMemoryFailure  -> "Memory allocation failure."
            kCCAlignmentError -> "Input size was not aligned properly."
            kCCDecodeError    -> "Input data did not decode or decrypt properly."
            kCCUnimplemented  -> "Function not implemented for the current algorithm."
            else              -> "CCCrypt failed with code $result"
        }
        throw CryptographyException(error)
    }
}
