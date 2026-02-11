/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkHmac(
    private val state: JdkCryptographyState,
) : BaseHmac() {

    override fun blockSize(digest: CryptographyAlgorithmId<Digest>): Int = digest.blockSize()

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, rawKey: ByteArray): HMAC.Key = HmacKey(digest, rawKey)

    private inner class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val secretKey: JSecretKey = SecretKeySpec(key, "Hmac${digest.hashAlgorithmName()}")
        private val signature = JdkMacSignature(state, secretKey, secretKey.algorithm)
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
    else -> throw IllegalStateException("Unsupported hash algorithm: $this")
}
