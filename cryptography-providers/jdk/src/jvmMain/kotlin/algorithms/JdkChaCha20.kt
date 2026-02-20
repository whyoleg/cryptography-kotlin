/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

private const val nonceSize: Int = 12

internal class JdkChaCha20(
    private val state: JdkCryptographyState,
) : ChaCha20 {
    private val keyWrapper: (JSecretKey) -> ChaCha20.Key = { key -> JdkChaCha20Key(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<ChaCha20.Key.Format, _>("ChaCha20", keyWrapper)

    override fun keyDecoder(): Decoder<ChaCha20.Key.Format, ChaCha20.Key> = keyDecoder
    override fun keyGenerator(): KeyGenerator<ChaCha20.Key> =
        JdkSecretKeyGenerator(state, "ChaCha20", keyWrapper) {
            init(state.secureRandom)
        }
}

private class JdkChaCha20Key(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : ChaCha20.Key, JdkEncodableKey<ChaCha20.Key.Format>(key) {
    override fun cipher(): IvCipher = JdkChaCha20IvCipher(state, key)

    override fun encodeToByteArrayBlocking(format: ChaCha20.Key.Format): ByteArray = when (format) {
        ChaCha20.Key.Format.RAW -> encodeToRaw()
    }
}

// JDK's standalone ChaCha20 cipher requires ChaCha20ParameterSpec (not IvParameterSpec).
// Supports two IV formats:
//   - 12-byte IV: treated as nonce, counter defaults to 1 (RFC 8439 Section 2.4)
//   - 16-byte IV: first 4 bytes are little-endian counter, remaining 12 bytes are nonce
// This allows callers to control the initial block counter (e.g. SSH chacha20-poly1305@openssh.com
// needs counter=0 for Poly1305 key derivation and counter=1 for message encryption).
private class JdkChaCha20IvCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : BaseIvCipher {
    private val cipher = state.cipher("ChaCha20")

    override fun createEncryptFunction(): CipherFunction {
        val nonce = ByteArray(nonceSize).also(state.secureRandom::nextBytes)
        return BaseImplicitIvEncryptFunction(nonce, createEncryptFunctionWithIv(nonce))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseImplicitIvDecryptFunction(nonceSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        val (nonce, counter) = parseIv(iv)
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, ChaCha20ParameterSpec(nonce, counter), state.secureRandom)
        })
    }

    // Called by BaseImplicitIvDecryptFunction — iv is the full ciphertext, extract nonceSize bytes.
    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        val nonce = iv.copyOfRange(startIndex, startIndex + nonceSize)
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, ChaCha20ParameterSpec(nonce, 1), state.secureRandom)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        val (nonce, counter) = parseIv(iv)
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, ChaCha20ParameterSpec(nonce, counter), state.secureRandom)
        })
    }
}

// Parses IV into (nonce, counter) pair.
// 12-byte IV: nonce only, counter = 1 (RFC 8439 Section 2.4 default).
// 16-byte IV: first 4 bytes = little-endian counter, next 12 bytes = nonce.
private fun parseIv(iv: ByteArray): Pair<ByteArray, Int> {
    return when (iv.size) {
        nonceSize -> iv to 1
        nonceSize + 4 -> {
            val counter = (iv[0].toInt() and 0xFF) or
                ((iv[1].toInt() and 0xFF) shl 8) or
                ((iv[2].toInt() and 0xFF) shl 16) or
                ((iv[3].toInt() and 0xFF) shl 24)
            val nonce = iv.copyOfRange(4, 4 + nonceSize)
            nonce to counter
        }
        else -> error("ChaCha20 IV must be $nonceSize bytes (nonce) or ${nonceSize + 4} bytes (counter + nonce), got ${iv.size}")
    }
}
