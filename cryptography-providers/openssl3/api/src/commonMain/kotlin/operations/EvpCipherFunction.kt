/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

@OptIn(UnsafeNumber::class)
private fun EVP_CIPHER_CTX(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray?,
    ivStartIndex: Int,
    encrypt: Boolean,
    createParams: MemScope.() -> CValuesRef<OSSL_PARAM>? = { null },
    configureContext: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): Resource<CPointer<EVP_CIPHER_CTX>?> = memScoped {
    val context = checkError(EVP_CIPHER_CTX_new())
    val resource = Resource<CPointer<EVP_CIPHER_CTX>?>(context, ::EVP_CIPHER_CTX_free)
    try {
        // two-step initialization, as we need to set `params` first, and then set key and iv
        // this is required for AES CCM
        checkError(
            EVP_CipherInit_ex2(
                ctx = context,
                cipher = cipher,
                key = null,
                iv = null,
                params = createParams(),
                enc = if (encrypt) 1 else 0
            )
        )

        checkError(
            EVP_CipherInit_ex2(
                ctx = context,
                cipher = null, // Note: `null` to a `cipher`
                key = key.refToU(0),
                iv = iv?.refToU(ivStartIndex),
                params = null,
                enc = if (encrypt) 1 else 0
            )
        )

        configureContext(context)
    } catch (cause: Throwable) {
        resource.close()
        throw cause
    }
    resource
}

// no iv
internal fun EvpCipherFunction(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    encrypt: Boolean,
    configureContext: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): CipherFunction = EvpCipherFunction(
    EVP_CIPHER_CTX(
        cipher = cipher,
        key = key,
        iv = null,
        ivStartIndex = 0,
        encrypt = encrypt,
        configureContext = configureContext
    )
)

// iv
internal fun EvpCipherFunction(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray,
    ivStartIndex: Int,
    encrypt: Boolean,
    configureContext: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): CipherFunction = EvpCipherFunction(
    EVP_CIPHER_CTX(
        cipher = cipher,
        key = key,
        iv = iv,
        ivStartIndex = ivStartIndex,
        encrypt = encrypt,
        configureContext = configureContext
    )
)

// for GCM/CCM???
// aead, exposes `EvpCipherFunction` for aead operations
internal fun EvpCipherFunction(
    cipher: CPointer<EVP_CIPHER>?,
    key: ByteArray,
    iv: ByteArray,
    ivStartIndex: Int,
    encrypt: Boolean,
    associatedData: ByteArray?,
    createParams: MemScope.() -> CValuesRef<OSSL_PARAM>? = { null },
    configureContext: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
): EvpCipherFunction = EvpCipherFunction(
    EVP_CIPHER_CTX(
        cipher = cipher,
        key = key,
        iv = iv,
        ivStartIndex = ivStartIndex,
        encrypt = encrypt,
        createParams = createParams
    ) { context ->
        configureContext(context)

        // provide associatedData in the end of initialization, just before working with plaintext/ciphertext
        if (associatedData != null) {
            val dataOutMoved = alloc<IntVar>()
            associatedData.usePinned { ad ->
                checkError(
                    EVP_CipherUpdate(
                        ctx = context,
                        out = null,
                        outl = dataOutMoved.ptr,
                        `in` = ad.safeAddressOfU(0),
                        inl = associatedData.size
                    )
                )
                check(dataOutMoved.value == associatedData.size) { "Unexpected output length: got ${dataOutMoved.value} expected ${associatedData.size}" }
            }
        }
    }
)

internal class EvpCipherFunction(
    private val context: Resource<CPointer<EVP_CIPHER_CTX>?>,
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
                            out = destinationPinned.safeAddressOfU(destinationOffset),
                            outl = dataOutMoved.ptr,
                            `in` = sourcePinned.safeAddressOfU(startIndex),
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
                        outm = destinationPinned.safeAddressOfU(destinationOffset),
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

    fun aeadEncryptTransform(tagSize: Int, plaintext: ByteArray): ByteArray = use {
        it.transformAndFinalizeToByteArray(plaintext) + it.getAeadTag(tagSize)
    }

    fun aeadDecryptTransform(tagSize: Int, ciphertext: ByteArray): ByteArray = use {
        it.setAeadTag(tagSize, ciphertext, ciphertext.size - tagSize)
        it.transformAndFinalizeToByteArray(ciphertext, 0, ciphertext.size - tagSize)
    }

    // aead handling
    private fun getAeadTag(tagSize: Int): ByteArray {
        val context = context.access()

        val destination = ByteArray(tagSize)
        destination.usePinned { destinationPin ->
            checkError(
                EVP_CIPHER_CTX_ctrl(
                    ctx = context,
                    type = EVP_CTRL_AEAD_GET_TAG,
                    arg = tagSize,
                    ptr = destinationPin.safeAddressOf(0)
                )
            )
        }
        return destination
    }

    private fun setAeadTag(tagSize: Int, source: ByteArray, startIndex: Int) {
        val context = context.access()

        source.usePinned { sourcePin ->
            checkError(
                EVP_CIPHER_CTX_ctrl(
                    ctx = context,
                    type = EVP_CTRL_AEAD_SET_TAG,
                    arg = tagSize,
                    ptr = sourcePin.safeAddressOf(startIndex)
                )
            )
        }
    }
}
