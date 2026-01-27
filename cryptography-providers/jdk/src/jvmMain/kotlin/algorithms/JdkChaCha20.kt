/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*

@OptIn(DelicateCryptographyApi::class)
internal class JdkChaCha20(
    private val state: JdkCryptographyState,
) : ChaCha20 {
    private val keyWrapper: (JSecretKey) -> ChaCha20.Key = { key -> JdkChaCha20Key(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<ChaCha20.Key.Format, _>("ChaCha20", keyWrapper)

    override fun keyDecoder(): KeyDecoder<ChaCha20.Key.Format, ChaCha20.Key> = keyDecoder
    override fun keyGenerator(): KeyGenerator<ChaCha20.Key> =
        JdkSecretKeyGenerator(state, "ChaCha20", keyWrapper) {
            init(state.secureRandom)
        }
}

@OptIn(DelicateCryptographyApi::class)
private class JdkChaCha20Key(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : ChaCha20.Key, JdkEncodableKey<ChaCha20.Key.Format>(key) {
    override fun cipher(): IvCipher = JdkChaCha20Cipher(state, key)

    override fun encodeToByteArrayBlocking(format: ChaCha20.Key.Format): ByteArray = when (format) {
        ChaCha20.Key.Format.RAW -> encodeToRaw()
    }
}

private const val chachaNonceSize: Int = 12

// ChaCha20ParameterSpec is only available in JDK 11+, so we use reflection for JDK 8 compilation compatibility
private val chacha20ParameterSpecConstructor by lazy {
    Class.forName("javax.crypto.spec.ChaCha20ParameterSpec")
        .getConstructor(ByteArray::class.java, Int::class.javaPrimitiveType)
}

private fun createChaCha20ParameterSpec(nonce: ByteArray, counter: Int): AlgorithmParameterSpec {
    return chacha20ParameterSpecConstructor.newInstance(nonce, counter) as AlgorithmParameterSpec
}

private class JdkChaCha20Cipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : BaseIvCipher {
    private val cipher = state.cipher("ChaCha20")

    override fun createEncryptFunction(): CipherFunction {
        val iv = ByteArray(chachaNonceSize).also(state.secureRandom::nextBytes)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseImplicitIvDecryptFunction(chachaNonceSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, createChaCha20ParameterSpec(iv, 0), state.secureRandom)
        })
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        val nonce = if (startIndex == 0) iv else iv.copyOfRange(startIndex, startIndex + chachaNonceSize)
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, createChaCha20ParameterSpec(nonce, 0), state.secureRandom)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}