/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

@OptIn(ExperimentalNativeApi::class)
internal object Openssl3AesCmac : AES.CMAC, BaseAes<AES.CMAC.Key>() {
    val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    // is it needed at all for `object`?
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(Openssl3Hmac.mac, ::EVP_MAC_free)

    override fun wrapKey(rawKey: ByteArray): AES.CMAC.Key = AesCmacKey(rawKey)

    private class AesCmacKey(key: ByteArray) : AES.CMAC.Key, BaseKey(key) {
        private val algorithm = when (key.size.bytes) {
            AES.Key.Size.B128 -> "AES-128-CBC"
            AES.Key.Size.B192 -> "AES-192-CBC"
            AES.Key.Size.B256 -> "AES-256-CBC"
            else              -> error("Unsupported key size")
        }
        private val signature = AesCmacSignature(algorithm = algorithm, key = key)
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}

private class AesCmacSignature(
    private val algorithm: String,
    private val key: ByteArray,
) : EvpMac(Openssl3AesCmac.mac, key) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("cipher".cstr.ptr, algorithm.cstr.ptr, 0.convert())
    )
}
