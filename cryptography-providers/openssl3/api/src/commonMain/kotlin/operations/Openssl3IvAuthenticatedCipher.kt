/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3IvAuthenticatedCipher(
    protected val cipher: CPointer<EVP_CIPHER>?,
    protected val key: ByteArray,
    protected val tagSize: Int,
    protected val implicitIvSize: Int, // for implicit cases
) : BaseIvAuthenticatedCipher {
    protected abstract fun MemScope.createParams(ivSize: Int): CValuesRef<OSSL_PARAM>?
    protected abstract fun MemScope.configureContext(context: CPointer<EVP_CIPHER_CTX>?, inputSize: Int)
    protected abstract fun validateIvSize(ivSize: Int)

    final override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(implicitIvSize)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    final override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        validateIvSize(iv.size)
        return AccumulatingCipherFunction { plaintext ->
            EvpCipherFunction(
                cipher = cipher,
                key = key,
                iv = iv,
                ivStartIndex = 0,
                encrypt = true,
                associatedData = associatedData,
                createParams = { createParams(iv.size) },
                configureContext = { configureContext(it, plaintext.size) },
            ).aeadEncryptTransform(tagSize, plaintext)
        }
    }

    final override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(implicitIvSize) { iv, startIndex ->
            createDecryptFunctionWithIv(iv, startIndex, implicitIvSize, associatedData)
        }
    }

    final override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }

    private fun createDecryptFunctionWithIv(
        iv: ByteArray,
        ivStartIndex: Int,
        ivSize: Int,
        associatedData: ByteArray?,
    ): CipherFunction {
        require(iv.size - ivStartIndex >= ivSize) { "IV bytes is not enough" }
        validateIvSize(ivSize)

        return AccumulatingCipherFunction { ciphertext ->
            EvpCipherFunction(
                cipher = cipher,
                key = key,
                iv = iv,
                ivStartIndex = ivStartIndex,
                encrypt = false,
                associatedData = associatedData,
                createParams = { createParams(ivSize) },
                configureContext = { configureContext(it, ciphertext.size - tagSize) },
            ).aeadDecryptTransform(tagSize, ciphertext)
        }
    }
}
