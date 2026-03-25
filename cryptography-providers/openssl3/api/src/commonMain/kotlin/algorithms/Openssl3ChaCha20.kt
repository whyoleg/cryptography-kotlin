/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

private const val keySize: Int = 32
private const val nonceSize: Int = 12

internal object Openssl3ChaCha20 : ChaCha20 {
    override fun keyDecoder(): Decoder<ChaCha20.Key.Format, ChaCha20.Key> = ChaCha20KeyDecoder()
    override fun keyGenerator(): KeyGenerator<ChaCha20.Key> = ChaCha20KeyGenerator()

    private class ChaCha20KeyDecoder : Decoder<ChaCha20.Key.Format, ChaCha20.Key> {
        override fun decodeFromByteArrayBlocking(format: ChaCha20.Key.Format, bytes: ByteArray): ChaCha20.Key = when (format) {
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

// OpenSSL's ChaCha20 cipher expects 16-byte IV (4-byte LE counter + 12-byte nonce).
// Supports two IV formats:
//   - 12-byte IV: treated as nonce, counter defaults to 1 (RFC 8439 Section 2.4)
//   - 16-byte IV: first 4 bytes are little-endian counter, remaining 12 bytes are nonce (passed directly)
// This allows callers to control the initial block counter (e.g. SSH chacha20-poly1305@openssh.com
// needs counter=0 for Poly1305 key derivation and counter=1 for message encryption).
private class Openssl3ChaCha20Cipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
) : BaseIvCipher {
    override fun createEncryptFunction(): CipherFunction {
        val nonce = CryptographySystem.getDefaultRandom().nextBytes(nonceSize)
        return BaseImplicitIvEncryptFunction(nonce, createEncryptFunctionWithIv(nonce))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseImplicitIvDecryptFunction(nonceSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return EvpCipherFunction(
            cipher = cipher,
            key = key,
            iv = toOpenSslIv(iv),
            ivStartIndex = 0,
            encrypt = true,
        )
    }

    // Called by BaseImplicitIvDecryptFunction — iv is the full ciphertext, extract nonceSize bytes.
    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        val result = ByteArray(16)
        result[0] = 1 // counter = 1 (little-endian)
        iv.copyInto(result, destinationOffset = 4, startIndex = startIndex, endIndex = startIndex + nonceSize)
        return EvpCipherFunction(
            cipher = cipher,
            key = key,
            iv = result,
            ivStartIndex = 0,
            encrypt = false,
        )
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return EvpCipherFunction(
            cipher = cipher,
            key = key,
            iv = toOpenSslIv(iv),
            ivStartIndex = 0,
            encrypt = false,
        )
    }
}

// Converts caller's IV to OpenSSL's 16-byte format (4-byte LE counter + 12-byte nonce).
// 12-byte IV: nonce only, counter = 1 (RFC 8439 Section 2.4 default).
// 16-byte IV: already in OpenSSL format, used directly.
private fun toOpenSslIv(iv: ByteArray): ByteArray {
    return when (iv.size) {
        nonceSize -> {
            val result = ByteArray(16)
            result[0] = 1 // counter = 1 (little-endian)
            iv.copyInto(result, destinationOffset = 4)
            result
        }
        nonceSize + 4 -> iv
        else -> error("ChaCha20 IV must be $nonceSize bytes (nonce) or ${nonceSize + 4} bytes (counter + nonce), got ${iv.size}")
    }
}
