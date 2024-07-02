/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal class CCCipher(
    private val algorithm: CCAlgorithm,
    private val mode: CCMode,
    private val padding: CCPadding,
    private val key: ByteArray,
) {
    fun encrypt(iv: ByteArray?, plaintext: ByteArray): ByteArray = memScoped {
        useCryptor { cryptorRef ->
            cryptorRef.create(kCCEncrypt, iv?.refTo(0))
            val ciphertextOutput = ByteArray(cryptorRef.outputLength(plaintext.size))

            val dataOutMoved = alloc<size_tVar>()
            val moved = cryptorRef.update(
                dataIn = plaintext.fixEmpty().refTo(0),
                dataInLength = plaintext.size,
                dataOut = ciphertextOutput.fixEmpty().refTo(0),
                dataOutAvailable = ciphertextOutput.size,
                dataOutMoved = dataOutMoved,
            )

            if (ciphertextOutput.size != moved) cryptorRef.final(
                dataOut = ciphertextOutput.refTo(moved),
                dataOutAvailable = ciphertextOutput.size - moved,
                dataOutMoved = dataOutMoved,
            )
            ciphertextOutput
        }
    }

    fun decrypt(iv: ByteArray?, ciphertext: ByteArray, ciphertextStartIndex: Int): ByteArray = memScoped {
        useCryptor { cryptorRef ->
            cryptorRef.create(kCCDecrypt, iv?.refTo(0))

            val plaintextOutput = ByteArray(cryptorRef.outputLength(ciphertext.size - ciphertextStartIndex))

            val dataOutMoved = alloc<size_tVar>()
            var moved = cryptorRef.update(
                dataIn = ciphertext.refToFixed(ciphertextStartIndex),
                dataInLength = ciphertext.size - ciphertextStartIndex,
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

    private inline fun <T> MemScope.useCryptor(block: (cryptorRef: CCCryptorRefVar) -> T): T {
        val cryptorRef = alloc<CCCryptorRefVar>()
        try {
            return block(cryptorRef)
        } finally {
            CCCryptorRelease(cryptorRef.value)
        }
    }

    private fun CCCryptorRefVar.create(op: CCOperation, iv: CValuesRef<*>?) {
        checkResult(
            CCCryptorCreateWithMode(
                op = op,
                cryptorRef = ptr,
                alg = algorithm,
                mode = mode,
                padding = padding,
                key = key.refTo(0),
                keyLength = key.size.convert(),
                iv = iv,

                // unused options
                options = 0.convert(),
                tweak = null,
                tweakLength = 0.convert(),
                numRounds = 0,
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
