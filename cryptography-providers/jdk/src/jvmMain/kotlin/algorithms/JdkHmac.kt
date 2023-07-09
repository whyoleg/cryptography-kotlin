/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*

internal class JdkHmac(
    private val state: JdkCryptographyState,
) : HMAC {
    private val keyWrapper: (JSecretKey) -> HMAC.Key = { key ->
        object : HMAC.Key, EncodableKey<HMAC.Key.Format> by JdkEncodableKey(key, "EC") {
            private val signature = JdkMacSignature(state, key, key.algorithm)
            override fun signatureGenerator(): SignatureGenerator = signature
            override fun signatureVerifier(): SignatureVerifier = signature
        }
    }

    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        return JdkSecretKeyDecoder("Hmac${digest.hashAlgorithmName()}", keyWrapper)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        return JdkSecretKeyGenerator(state, "Hmac${digest.hashAlgorithmName()}", keyWrapper) {
            init(digest.blockSize(), state.secureRandom)
        }
    }
}

private fun CryptographyAlgorithmId<Digest>.blockSize(): Int = when (this) {
    SHA1   -> 64
    SHA256 -> 64
    SHA384 -> 128
    SHA512 -> 128
    else   -> throw CryptographyException("Unsupported hash algorithm: $this")
} * 8
