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
// Counter starts at 1, matching RFC 8439 Section 2.4 (counter=0 is reserved for Poly1305 key in AEAD).
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
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, ChaCha20ParameterSpec(iv, 1), state.secureRandom)
        })
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        val nonce = if (startIndex == 0 && iv.size == nonceSize) iv else iv.copyOfRange(startIndex, startIndex + nonceSize)
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, ChaCha20ParameterSpec(nonce, 1), state.secureRandom)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}
