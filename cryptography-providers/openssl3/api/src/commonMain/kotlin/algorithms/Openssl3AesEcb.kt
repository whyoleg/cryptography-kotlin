/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesEcb : AES.ECB, Openssl3Aes<AES.ECB.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.ECB.Key = AesEcbKey(keySize, key)

    private class AesEcbKey(keySize: BinarySize, key: ByteArray) : AES.ECB.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-ECB"
            AES.Key.Size.B192 -> "AES-192-ECB"
            AES.Key.Size.B256 -> "AES-256-ECB"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(padding: Boolean): Cipher {
            return Openssl3AesEcbCipher(cipher, key) { context ->
                checkError(EVP_CIPHER_CTX_set_padding(context, if (padding) 1 else 0))
            }
        }

        private class Openssl3AesEcbCipher(
            private val cipher: CPointer<EVP_CIPHER>?,
            private val key: ByteArray,
            private val init: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
        ) : BaseCipher {
            override fun createEncryptFunction(): CipherFunction = EvpCipherFunction(cipher, key, encrypt = true, init)
            override fun createDecryptFunction(): CipherFunction = EvpCipherFunction(cipher, key, encrypt = false, init)
        }
    }
}
