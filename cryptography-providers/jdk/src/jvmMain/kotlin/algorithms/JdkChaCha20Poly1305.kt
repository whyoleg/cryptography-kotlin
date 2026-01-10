/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkChaCha20Poly1305(
    private val state: JdkCryptographyState,
) : ChaCha20Poly1305 {
    private val keyWrapper: (JSecretKey) -> ChaCha20Poly1305.Key = { key -> JdkChaCha20Poly1305Key(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<ChaCha20Poly1305.Key.Format, _>("ChaCha20", keyWrapper)

    override fun keyDecoder(): KeyDecoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> = keyDecoder
    override fun keyGenerator(): KeyGenerator<ChaCha20Poly1305.Key> =
        JdkSecretKeyGenerator(state, "ChaCha20", keyWrapper) {
            init(state.secureRandom)
        }
}

private class JdkChaCha20Poly1305Key(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : ChaCha20Poly1305.Key, JdkEncodableKey<ChaCha20Poly1305.Key.Format>(key) {
    override fun cipher(): IvAuthenticatedCipher = JdkChaCha20Poly1305Cipher(state, key)

    override fun encodeToByteArrayBlocking(format: ChaCha20Poly1305.Key.Format): ByteArray = when (format) {
        ChaCha20Poly1305.Key.Format.JWK -> error("$format is not supported")
        ChaCha20Poly1305.Key.Format.RAW -> encodeToRaw()
    }
}

private const val chachaNonceSize: Int = 12

private class JdkChaCha20Poly1305Cipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : BaseIvAuthenticatedCipher {
    private val cipher = state.cipher("ChaCha20-Poly1305")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = ByteArray(chachaNonceSize).also(state.secureRandom::nextBytes)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(chachaNonceSize) { iv: ByteArray, startIndex: Int ->
            createDecryptFunctionWithIv(iv, startIndex, chachaNonceSize, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
            associatedData?.let(this::updateAAD)
        })
    }

    private fun createDecryptFunctionWithIv(
        iv: ByteArray,
        startIndex: Int,
        ivSize: Int,
        associatedData: ByteArray?,
    ): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, IvParameterSpec(iv, startIndex, ivSize), state.secureRandom)
            associatedData?.let(this::updateAAD)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }
}
