/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkHmac(
    private val state: JdkCryptographyState,
) : BaseHmac<JdkHmac.HmacDigest>() {
    class HmacDigest(val algorithm: String, val mac: Pooled<JMac>, val blockSize: Int)

    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): HmacDigest {
        val algorithm = "Hmac${digest.hashAlgorithmName()}"
        return HmacDigest(algorithm, state.mac(algorithm), digest.blockSize())
    }

    override fun blockSize(digest: HmacDigest): Int = digest.blockSize

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, resolvedDigest: HmacDigest, rawKey: ByteArray): HMAC.Key =
        HmacKey(digest, resolvedDigest, rawKey)

    private inner class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        resolvedDigest: HmacDigest,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val signature = JdkMacSignature(resolvedDigest.mac, SecretKeySpec(key, resolvedDigest.algorithm))
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}

private fun CryptographyAlgorithmId<Digest>.blockSize(): Int = when (this) {
    SHA1     -> 64
    SHA224   -> 64
    SHA256   -> 64
    SHA384   -> 128
    SHA512   -> 128
    SHA3_224 -> 144
    SHA3_256 -> 136
    SHA3_384 -> 104
    SHA3_512 -> 72
    else -> unsupportedParameter("hash algorithm", name)
}
