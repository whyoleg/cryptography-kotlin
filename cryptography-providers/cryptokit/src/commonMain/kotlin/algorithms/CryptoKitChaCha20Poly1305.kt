/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import platform.Foundation.*

private const val keySize = 32
private const val nonceSize: Int = 12
private const val tagSize: Int = 16

internal object CryptoKitChaCha20Poly1305 : ChaCha20Poly1305 {
    override fun keyDecoder(): KeyDecoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyDecoder()
    override fun keyGenerator(): KeyGenerator<ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyGenerator()
}

private class ChaCha20Poly1305KeyDecoder : KeyDecoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> {
    override fun decodeFromByteArrayBlocking(format: ChaCha20Poly1305.Key.Format, bytes: ByteArray): ChaCha20Poly1305.Key = when (format) {
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
    override fun cipher(): IvAuthenticatedCipher = ChaCha20Poly1305Cipher(key)

    override fun encodeToByteArrayBlocking(format: ChaCha20Poly1305.Key.Format): ByteArray = when (format) {
        ChaCha20Poly1305.Key.Format.RAW -> key.copyOf()
        ChaCha20Poly1305.Key.Format.JWK -> error("JWK is not supported")
    }
}


private class ChaCha20Poly1305Cipher(
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

        return AccumulatingCipherFunction { plaintext ->
            plaintext.useNSData { plaintextData ->
                iv.useNSData { ivData ->
                    key.useNSData { keyData ->
                        (associatedData ?: EmptyByteArray).useNSData { adData ->
                            swiftTry { error ->
                                DwcChaCha20Poly1305.encryptWithKey(
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
        require(ivSize >= nonceSize) { "IV size is wrong" }
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return AccumulatingCipherFunction { ciphertext ->
            ciphertext.useNSData(endIndex = ciphertext.size - tagSize) { ciphertextData ->
                ciphertext.useNSData(startIndex = ciphertext.size - tagSize) { tagData ->
                    iv.useNSData(startIndex, startIndex + ivSize) { ivData ->
                        key.useNSData { keyData ->
                            (associatedData ?: EmptyByteArray).useNSData { adData ->
                                swiftTry { error ->
                                    DwcChaCha20Poly1305.decryptWithKey(
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
