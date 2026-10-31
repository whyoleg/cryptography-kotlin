/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Hmac : BaseHmac<Openssl3Hmac.HmacDigest>() {
    val mac = NativeResource(checkError(EVP_MAC_fetch(null, "HMAC", null)), ::EVP_MAC_free)

    class HmacDigest(val name: String, val blockSize: Int)

    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): HmacDigest {
        val name = hashAlgorithmName(digest)
        return HmacDigest(name, blockSize(name))
    }

    override fun blockSize(digest: HmacDigest): Int = digest.blockSize

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, resolvedDigest: HmacDigest, rawKey: ByteArray): HMAC.Key =
        HmacKey(digest, resolvedDigest, rawKey)

    private class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        resolvedDigest: HmacDigest,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val signature = HmacSignature(resolvedDigest.name, key)
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
