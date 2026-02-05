/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

private const val keySize: Int = 32
private const val nonceSize: Int = 12
private const val tagSize: Int = 16

internal object Openssl3ChaCha20Poly1305 : ChaCha20Poly1305 {
    override fun keyDecoder(): Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyDecoder()
    override fun keyGenerator(): KeyGenerator<ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyGenerator()

    private class ChaCha20Poly1305KeyDecoder : Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> {
        override fun decodeFromByteArrayBlocking(format: ChaCha20Poly1305.Key.Format, bytes: ByteArray): ChaCha20Poly1305.Key =
            when (format) {
                ChaCha20Poly1305.Key.Format.RAW -> {
                    require(bytes.size == keySize) { "ChaCha20-Poly1305 key size must be 256 bits" }
                    ChaCha20Poly1305Key(bytes.copyOf())
                }
                ChaCha20Poly1305.Key.Format.JWK -> error("JWK is not supported")
            }
    }

    private class ChaCha20Poly1305KeyGenerator : KeyGenerator<ChaCha20Poly1305.Key> {
        override fun generateKeyBlocking(): ChaCha20Poly1305.Key {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySize)
            return ChaCha20Poly1305Key(key)
        }
    }

    private class ChaCha20Poly1305Key(private val key: ByteArray) : ChaCha20Poly1305.Key {
        private val cipher = EVP_CIPHER_fetch(null, "ChaCha20-Poly1305", null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): IvAuthenticatedCipher = Openssl3ChaCha20Poly1305Cipher(cipher, key)

        override fun encodeToByteArrayBlocking(format: ChaCha20Poly1305.Key.Format): ByteArray = when (format) {
            ChaCha20Poly1305.Key.Format.RAW -> key.copyOf()
            ChaCha20Poly1305.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}

private class Openssl3ChaCha20Poly1305Cipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
) : BaseIvAuthenticatedCipher {

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(nonceSize)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(nonceSize) { iv, startIndex ->
            createDecryptFunctionWithIv(iv, startIndex, nonceSize, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        require(iv.size >= nonceSize) { "IV size is wrong" }

        return ChaCha20Poly1305EncryptFunction(createContext(iv, 0, iv.size, encrypt = true, associatedData))
    }

    private fun createDecryptFunctionWithIv(
        iv: ByteArray,
        startIndex: Int,
        ivSize: Int,
        associatedData: ByteArray?,
    ): CipherFunction {
        require(ivSize == nonceSize) { "IV size is wrong" }
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return AccumulatingCipherFunction { input ->
            ChaCha20Poly1305DecryptFunction(createContext(iv, startIndex, ivSize, encrypt = false, associatedData))
                .use { it.decrypt(input) }
        }
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }

    private fun createContext(
        iv: ByteArray,
        ivStartIndex: Int,
        ivSize: Int,
        encrypt: Boolean,
        associatedData: ByteArray?,
    ): Resource<CPointer<EVP_CIPHER_CTX>?> {
        return EVP_CIPHER_CTX(cipher, key, iv, ivStartIndex, encrypt, ivSize) { context ->
            if (associatedData == null) return@EVP_CIPHER_CTX
            memScoped {
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
    }

    private class ChaCha20Poly1305EncryptFunction(
        context: Resource<CPointer<EVP_CIPHER_CTX>?>,
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

    private class ChaCha20Poly1305DecryptFunction(
        context: Resource<CPointer<EVP_CIPHER_CTX>?>,
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
