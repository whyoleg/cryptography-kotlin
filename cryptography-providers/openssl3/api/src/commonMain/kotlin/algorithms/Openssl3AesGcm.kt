/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesGcm : AES.GCM, Openssl3Aes<AES.GCM.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.GCM.Key = AesGcmKey(keySize, key)

    private class AesGcmKey(keySize: BinarySize, key: ByteArray) : AES.GCM.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-GCM"
            AES.Key.Size.B192 -> "AES-192-GCM"
            AES.Key.Size.B256 -> "AES-256-GCM"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(tagSize: BinarySize): IvAuthenticatedCipher = Openssl3AesGcmCipher(tagSize.inBytes)

        private inner class Openssl3AesGcmCipher(tabSizeBytes: Int) : Openssl3IvAuthenticatedCipher(
            cipher = cipher,
            key = key,
            tagSize = tabSizeBytes,
            implicitIvSize = 12
        ) {
            @OptIn(UnsafeNumber::class)
            override fun MemScope.createParams(ivSize: Int): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
                OSSL_PARAM_construct_size_t("ivlen".cstr.ptr, alloc(ivSize.convert<size_t>()).ptr),
            )

            override fun MemScope.configureContext(context: CPointer<EVP_CIPHER_CTX>?, inputSize: Int) {}
            override fun validateIvSize(ivSize: Int) {
                require(ivSize >= implicitIvSize) { "IV size is wrong" }
            }
        }
    }
}
