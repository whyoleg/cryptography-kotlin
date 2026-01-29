/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
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
// OpenSSL uses 16-byte IV: 4-byte counter (little-endian) + 12-byte nonce
private const val ivSize: Int = 16

@OptIn(DelicateCryptographyApi::class)
internal object Openssl3ChaCha20 : ChaCha20 {
    override fun keyDecoder(): KeyDecoder<ChaCha20.Key.Format, ChaCha20.Key> = ChaCha20KeyDecoder()
    override fun keyGenerator(): KeyGenerator<ChaCha20.Key> = ChaCha20KeyGenerator()

    private class ChaCha20KeyDecoder : KeyDecoder<ChaCha20.Key.Format, ChaCha20.Key> {
        override fun decodeFromByteArrayBlocking(format: ChaCha20.Key.Format, bytes: ByteArray): ChaCha20.Key =
            when (format) {
                ChaCha20.Key.Format.RAW -> {
                    require(bytes.size == keySize) { "ChaCha20 key size must be 256 bits" }
                    ChaCha20Key(bytes.copyOf())
                }
            }
    }

    private class ChaCha20KeyGenerator : KeyGenerator<ChaCha20.Key> {
        override fun generateKeyBlocking(): ChaCha20.Key {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySize)
            return ChaCha20Key(key)
        }
    }

    private class ChaCha20Key(private val key: ByteArray) : ChaCha20.Key {
        private val cipher = EVP_CIPHER_fetch(null, "ChaCha20", null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): IvCipher = Openssl3ChaCha20Cipher(cipher, key)

        override fun encodeToByteArrayBlocking(format: ChaCha20.Key.Format): ByteArray = when (format) {
            ChaCha20.Key.Format.RAW -> key.copyOf()
        }
    }
}

@OptIn(DelicateCryptographyApi::class)
private class Openssl3ChaCha20Cipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
) : BaseIvCipher {

    // Convert 12-byte nonce to 16-byte IV
    // OpenSSL RFC 7539 ChaCha20: counter (4 bytes LE) + nonce (12 bytes)
    private fun nonceToIv(nonce: ByteArray, startIndex: Int = 0): ByteArray {
        val iv = ByteArray(ivSize)
        // Counter is first 4 bytes, little-endian, set to 0
        // iv[0..3] = 0 (already zero)
        // Copy nonce to bytes 4..15
        nonce.copyInto(iv, destinationOffset = 4, startIndex = startIndex, endIndex = startIndex + nonceSize)
        return iv
    }

    override fun createEncryptFunction(): CipherFunction {
        val nonce = CryptographySystem.getDefaultRandom().nextBytes(nonceSize)
        return BaseImplicitIvEncryptFunction(nonce, createEncryptFunctionWithIv(nonce))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseImplicitIvDecryptFunction(nonceSize) { nonce, startIndex ->
            createDecryptFunctionWithNonce(nonce, startIndex)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        require(iv.size >= nonceSize) { "Nonce size must be at least $nonceSize bytes" }
        val fullIv = nonceToIv(iv)
        return EvpCipherFunction(cipher, key, fullIv, 0, encrypt = true)
    }

    private fun createDecryptFunctionWithNonce(
        nonce: ByteArray,
        startIndex: Int,
    ): CipherFunction {
        require(nonce.size - startIndex >= nonceSize) { "Nonce size is wrong" }
        val fullIv = nonceToIv(nonce, startIndex)
        return EvpCipherFunction(cipher, key, fullIv, 0, encrypt = false)
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithNonce(iv, 0)
    }
}
