/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesGcm : AES.GCM, Openssl3Aes<AES.GCM.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.GCM.Key = AesGcmKey(keySize, key)

    private class AesGcmKey(keySize: BinarySize, key: ByteArray) : AES.GCM.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-GCM"
            AES.Key.Size.B192 -> "AES-192-GCM"
            AES.Key.Size.B256 -> "AES-256-GCM"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(tagSize: BinarySize): AES.IvAuthenticatedCipher {
            return Openssl3AesGcmCipher(cipher, key, tagSize.inBytes)
        }
    }
}

private class Openssl3AesGcmCipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
    private val tagSize: Int,
) : BaseAesIvAuthenticatedCipher {
    private val ivSize: Int get() = 12

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = CryptographyRandom.nextBytes(ivSize)
        return BaseAesImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseAesImplicitIvDecryptFunction(ivSize) { iv, startIndex ->
            createDecryptFunctionWithIv(iv, startIndex, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        require(iv.size == ivSize) { "IV size is wrong" }

        return AesGcmEncryptFunction(createContext(iv, 0, encrypt = true, associatedData), tagSize)
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int, associatedData: ByteArray?): CipherFunction {
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        // GCM should validate data at the end, so it's not really streaming
        return AccumulatingCipherFunction { input ->
            AesGcmDecryptFunction(createContext(iv, startIndex, encrypt = false, associatedData), tagSize)
                .use { it.decrypt(input) }
        }
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, associatedData)
    }

    private fun createContext(
        iv: ByteArray,
        ivStartIndex: Int,
        encrypt: Boolean,
        associatedData: ByteArray?,
    ): Resource<CPointer<EVP_CIPHER_CTX>?> {
        return EVP_CIPHER_CTX(cipher, key, iv, ivStartIndex, encrypt) { context ->
            if (associatedData == null) return@EVP_CIPHER_CTX
            memScoped {
                val dataOutMoved = alloc<IntVar>()
                associatedData.usePinned { ad ->
                    checkError(
                        EVP_CipherUpdate(
                            ctx = context,
                            out = null,
                            outl = dataOutMoved.ptr,
                            `in` = ad.safeAddressOf(0).reinterpret(),
                            inl = associatedData.size
                        )
                    )
                    check(dataOutMoved.value == associatedData.size) { "Unexpected output length: got ${dataOutMoved.value} expected ${associatedData.size}" }
                }
            }
        }
    }

    private class AesGcmEncryptFunction(
        context: Resource<CPointer<EVP_CIPHER_CTX>?>,
        private val tagSize: Int,
    ) : EvpCipherFunction(context) {
        override fun maxOutputSize(inputSize: Int): Int {
            return inputSize + tagSize
        }

        override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val finalizeOffset = super.finalizeIntoByteArray(destination, destinationOffset)
            val tagOffset = getTagIntoByteArray(destination, destinationOffset + finalizeOffset)
            return finalizeOffset + tagOffset
        }

        private fun getTagIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val context = context.access()

            destination.usePinned { destinationPin ->
                checkError(
                    EVP_CIPHER_CTX_ctrl(
                        ctx = context,
                        type = EVP_CTRL_AEAD_GET_TAG,
                        arg = tagSize,
                        ptr = destinationPin.safeAddressOf(destinationOffset)
                    )
                )
            }

            return tagSize
        }
    }

    private class AesGcmDecryptFunction(
        context: Resource<CPointer<EVP_CIPHER_CTX>?>,
        private val tagSize: Int,
    ) : EvpCipherFunction(context) {
        fun decrypt(input: ByteArray): ByteArray {
            val transformed = transformToByteArray(input, endIndex = input.size - tagSize)
            setTag(input, input.size - tagSize)
            val finalized = finalizeToByteArray()
            return transformed + finalized
        }

        private fun setTag(source: ByteArray, startIndex: Int) {
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
}
