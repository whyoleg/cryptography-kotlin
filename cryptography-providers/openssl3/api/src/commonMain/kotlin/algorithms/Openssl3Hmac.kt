/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Hmac : BaseHmac() {
    val mac = checkError(EVP_MAC_fetch(null, "HMAC", null))

    // is it needed at all for `object`?
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

    override fun blockSize(digest: CryptographyAlgorithmId<Digest>): Int = blockSize(hashAlgorithmName(digest))

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, rawKey: ByteArray): HMAC.Key = HmacKey(digest, rawKey)

    private class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val signature = HmacSignature(hashAlgorithmName(digest), key)
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}

private class HmacSignature(private val hashAlgorithm: String, key: ByteArray) : EvpMac(Openssl3Hmac.mac, key) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert())
    )
}
