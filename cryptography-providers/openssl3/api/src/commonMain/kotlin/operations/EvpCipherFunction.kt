/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal fun EVP_CIPHER_CTX(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray?,
    ivStartIndex: Int,
    encrypt: Boolean,
    init: (CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): Resource<CPointer<EVP_CIPHER_CTX>?> {
    val context = checkError(EVP_CIPHER_CTX_new())
    val resource = Resource<CPointer<EVP_CIPHER_CTX>?>(context, ::EVP_CIPHER_CTX_free)
    try {
        checkError(
            EVP_CipherInit_ex2(
                ctx = context,
                cipher = cipher,
                key = key.refToU(0),
                iv = iv?.refToU(ivStartIndex),
                params = null,
                enc = if (encrypt) 1 else 0
            )
        )
        init(context)
    } catch (cause: Throwable) {
        resource.close()
        throw cause
    }
    return resource
}

internal fun EvpCipherFunction(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray?,
    ivStartIndex: Int,
    encrypt: Boolean,
    init: (CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): CipherFunction {
    return EvpCipherFunction(EVP_CIPHER_CTX(cipher, key, iv, ivStartIndex, encrypt, init))
}

internal open class EvpCipherFunction(
    protected val context: Resource<CPointer<EVP_CIPHER_CTX>?>,
) : BaseCipherFunction() {
    private val closeable = SafeCloseable(SafeCloseAction(context, AutoCloseable::close))
    override val blockSize: Int // TODO: accepted value
        get() = checkError(EVP_CIPHER_CTX_get_block_size(context.access()))

    override fun maxOutputSize(inputSize: Int): Int {
        val blockSize = blockSize
        if (blockSize == 1) return inputSize
        return inputSize + blockSize
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

        val context = context.access()

        return memScoped {
            val dataOutMoved = alloc<IntVar>()
            source.usePinned { sourcePinned ->
                destination.usePinned { destinationPinned ->
                    checkError(
                        EVP_CipherUpdate(
                            ctx = context,
                            out = destinationPinned.safeAddressOf(destinationOffset).reinterpret(),
                            outl = dataOutMoved.ptr,
                            `in` = sourcePinned.safeAddressOf(startIndex).reinterpret(),
                            inl = (endIndex - startIndex).convert(),
                        )
                    )
                }
            }
            dataOutMoved.value.convert<Int>()
        }
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + maxOutputSize(0))

        val context = context.access()

        return memScoped {
            val dataOutMoved = alloc<IntVar>()
            destination.usePinned { destinationPinned ->
                checkError(
                    EVP_CipherFinal(
                        ctx = context,
                        outm = destinationPinned.safeAddressOf(destinationOffset).reinterpret(),
                        outl = dataOutMoved.ptr
                    )
                )
            }
            dataOutMoved.value.convert()
        }
    }

    override fun close() {
        closeable.close()
    }
}
