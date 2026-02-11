/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesCcm : AES.CCM, BaseAes<AES.CCM.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CCM.Key = AesCcmKey(rawKey)

    private class AesCcmKey(key: ByteArray) : AES.CCM.Key, BaseKey(key) {
        private val algorithm = when (key.size.bytes) {
            AES.Key.Size.B128 -> "AES-128-CCM"
            AES.Key.Size.B192 -> "AES-192-CCM"
            AES.Key.Size.B256 -> "AES-256-CCM"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(tagSize: BinarySize): IvAuthenticatedCipher = Openssl3AesCcmCipher(tagSize.inBytes)

        private inner class Openssl3AesCcmCipher(tagSize: Int) : Openssl3IvAuthenticatedCipher(
            cipher = cipher,
            key = key,
            tagSize = tagSize,
            implicitIvSize = 12
        ) {
            @OptIn(UnsafeNumber::class)
            override fun MemScope.createParams(ivSize: Int): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
                OSSL_PARAM_construct_octet_string("tag".cstr.ptr, null, tagSize.convert()),
                OSSL_PARAM_construct_size_t("ivlen".cstr.ptr, alloc(ivSize.convert<size_t>()).ptr),
            )

            override fun MemScope.configureContext(context: CPointer<EVP_CIPHER_CTX>?, inputSize: Int) {
                // Provide the total plaintext/ciphertext length - required for AES CCM only
                val dataOutMoved = alloc<IntVar>()
                checkError(
                    EVP_CipherUpdate(
                        ctx = context,
                        out = null,
                        outl = dataOutMoved.ptr,
                        `in` = null,
                        inl = inputSize
                    )
                )
            }

            override fun validateIvSize(ivSize: Int) {
                require(ivSize in 7..13) { "CCM IV size must be between 7 and 13 bytes" }
            }
        }
    }
}
