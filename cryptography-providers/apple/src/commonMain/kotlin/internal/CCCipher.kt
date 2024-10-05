/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.posix.*

@Suppress("FunctionName")
@OptIn(UnsafeNumber::class)
internal fun CCCipherFunction(
    algorithm: CCAlgorithm,
    mode: CCMode,
    padding: CCPadding,
    operation: CCOperation,
    blockSize: Int,
    key: ByteArray,
    iv: ByteArray?,
    ivStartIndex: Int,
    validateFullInputSize: (Int) -> Unit = {},
): CipherFunction {
    val cryptorRef = nativeHeap.alloc<CCCryptorRefVar>()
    val resource = Resource(cryptorRef) {
        CCCryptorRelease(it.value)
        nativeHeap.free(cryptorRef)
    }
    try {
        checkResult(
            CCCryptorCreateWithMode(
                op = operation,
                cryptorRef = cryptorRef.ptr,
                alg = algorithm,
                mode = mode,
                padding = padding,
                key = key.refTo(0),
                keyLength = key.size.convert(),
                iv = iv?.refTo(ivStartIndex),

                // unused options
                options = 0.convert(),
                tweak = null,
                tweakLength = 0.convert(),
                numRounds = 0,
            )
        )
    } catch (cause: Throwable) {
        resource.close()
        throw cause
    }
    return CCCipherFunction(resource, blockSize, validateFullInputSize)
}

@OptIn(UnsafeNumber::class)
private class CCCipherFunction(
    private val cryptorRef: Resource<CCCryptorRefVar>,
    override val blockSize: Int,
    private val validateFullInputSize: (Int) -> Unit = {},
) : BaseCipherFunction(), AutoCloseable by SafeCloseable(SafeCloseAction(cryptorRef, AutoCloseable::close)) {
    private var fullInputSize = 0

    override fun maxOutputSize(inputSize: Int): Int {
        val cryptorRef = cryptorRef.access()
        return CCCryptorGetOutputLength(
            cryptorRef = cryptorRef.value,
            inputLength = inputSize.convert(),
            final = true
        ).convert()
    }

    override fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        checkBounds(source.size, startIndex, endIndex)
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(endIndex - startIndex))

        val cryptorRef = cryptorRef.access()

        return memScoped {
            val dataOutMoved = alloc<size_tVar>()
            source.usePinned { sourcePinned ->
                destination.usePinned { destinationPinned ->
                    checkResult(
                        CCCryptorUpdate(
                            cryptorRef = cryptorRef.value,
                            dataIn = sourcePinned.safeAddressOf(startIndex),
                            dataInLength = (endIndex - startIndex).convert(),
                            dataOut = destinationPinned.safeAddressOf(destinationOffset),
                            dataOutAvailable = (destination.size - destinationOffset).convert(),
                            dataOutMoved = dataOutMoved.ptr
                        )
                    )
                }
            }
            fullInputSize += (endIndex - startIndex)
            dataOutMoved.value.convert()
        }
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(0))

        val cryptorRef = cryptorRef.access()

        validateFullInputSize(fullInputSize)

        return memScoped {
            val dataOutMoved = alloc<size_tVar>()
            destination.usePinned { destinationPinned ->
                checkResult(
                    CCCryptorFinal(
                        cryptorRef = cryptorRef.value,
                        dataOut = destinationPinned.safeAddressOf(destinationOffset),
                        dataOutAvailable = (destination.size - destinationOffset).convert(),
                        dataOutMoved = dataOutMoved.ptr
                    )
                )
            }
            dataOutMoved.value.convert()
        }
    }
}

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

}

private fun checkResult(result: CCCryptorStatus) {
    error(
        when (result) {
            kCCSuccess        -> return
            kCCParamError     -> "Illegal parameter value."
            kCCBufferTooSmall -> "Insufficient buffer provided for specified operation."
            kCCMemoryFailure  -> "Memory allocation failure."
            kCCAlignmentError -> "Input size was not aligned properly."
            kCCDecodeError    -> "Input data did not decode or decrypt properly."
            kCCUnimplemented  -> "Function not implemented for the current algorithm."
            else              -> "CCCrypt failed with code $result"
        }
    )
}