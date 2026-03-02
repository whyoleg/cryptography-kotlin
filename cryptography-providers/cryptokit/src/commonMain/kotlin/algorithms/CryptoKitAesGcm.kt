/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*

internal object CryptoKitAesGcm : AES.GCM, BaseAes<AES.GCM.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.GCM.Key = AesGcmKey(rawKey)

    private class AesGcmKey(key: ByteArray) : AES.GCM.Key, BaseKey(key) {
        override fun cipher(tagSize: BinarySize): IvAuthenticatedCipher {
            require(tagSize == 16.bytes) { "GCM tag size must be 16 bytes, but was $tagSize" }
            return AesGcmCipher(key, tagSize.inBytes)
        }
    }
}

private const val defaultIvSize: Int = 12

private class AesGcmCipher(
    private val key: ByteArray,
    private val tagSize: Int,
) : BaseIvAuthenticatedCipher {

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(defaultIvSize)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(defaultIvSize) { iv, startIndex ->
            createDecryptFunctionWithIv(iv, startIndex, defaultIvSize, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        require(iv.size >= defaultIvSize) { "IV size is wrong" }

        return AccumulatingCipherFunction { plaintext ->
            plaintext.useNSData { plaintextData ->
                iv.useNSData { ivData ->
                    key.useNSData { keyData ->
                        (associatedData ?: EmptyByteArray).useNSData { adData ->
                            swiftTry { error ->
                                DwcAesGcm.encryptWithKey(
                                    key = keyData,
                                    nonce = ivData,
                                    plaintext = plaintextData,
                                    authenticatedData = adData,
                                    error = error
                                )
                            }.toByteArray().let {
                                it.copyOfRange(iv.size, it.size)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun createDecryptFunctionWithIv(
        iv: ByteArray,
        startIndex: Int,
        ivSize: Int,
        associatedData: ByteArray?,
    ): CipherFunction {
        require(ivSize >= defaultIvSize) { "IV size is wrong" }
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return AccumulatingCipherFunction { ciphertext ->
            ciphertext.useNSData(endIndex = ciphertext.size - tagSize) { ciphertextData ->
                ciphertext.useNSData(startIndex = ciphertext.size - tagSize) { tagData ->
                    iv.useNSData(startIndex, startIndex + ivSize) { ivData ->
                        key.useNSData { keyData ->
                            (associatedData ?: EmptyByteArray).useNSData { adData ->
                                swiftTry { error ->
                                    DwcAesGcm.decryptWithKey(
                                        key = keyData,
                                        nonce = ivData,
                                        ciphertext = ciphertextData,
                                        tag = tagData,
                                        authenticatedData = adData,
                                        error = error
                                    )
                                }.toByteArray()
                            }
                        }
                    }
                }
            }
        }
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }
}
