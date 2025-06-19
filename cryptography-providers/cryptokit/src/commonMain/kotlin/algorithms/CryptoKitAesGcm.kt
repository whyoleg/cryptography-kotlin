/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*

internal object CryptoKitAesGcm : AES.GCM {
    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.GCM.Key> = AesKeyDecoder()

    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.GCM.Key> = AesGcmKeyGenerator(keySize.inBytes)
}

private class AesKeyDecoder : KeyDecoder<AES.Key.Format, AES.GCM.Key> {
    override fun decodeFromByteArrayBlocking(format: AES.Key.Format, bytes: ByteArray): AES.GCM.Key = when (format) {
        AES.Key.Format.RAW -> {
            require(bytes.size == 16 || bytes.size == 24 || bytes.size == 32) {
                "AES key size must be 128, 192 or 256 bits"
            }
            AesGcmKey(bytes.copyOf())
        }
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class AesGcmKeyGenerator(private val keySizeBytes: Int) : KeyGenerator<AES.GCM.Key> {
    override fun generateKeyBlocking(): AES.GCM.Key {
        val key = CryptographySystem.getDefaultRandom().nextBytes(keySizeBytes)
        return AesGcmKey(key)
    }
}

private class AesGcmKey(private val key: ByteArray) : AES.GCM.Key {
    override fun cipher(tagSize: BinarySize): AES.IvAuthenticatedCipher {
        require(tagSize == 16.bytes) { "GCM tag size must be 16 bytes, but was $tagSize" }
        return AesGcmCipher(key, tagSize.inBytes)
    }

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.RAW -> key.copyOf()
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private const val defaultIvSize: Int = 12

private class AesGcmCipher(
    private val key: ByteArray,
    private val tagSize: Int,
) : BaseAesIvAuthenticatedCipher {

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(defaultIvSize)
        return BaseAesImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseAesImplicitIvDecryptFunction(defaultIvSize) { iv, startIndex ->
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
                                SwiftAesGcm.encryptWithKey(
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
                                    SwiftAesGcm.decryptWithKey(
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
