/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*

@CryptographyProviderApi
public abstract class BaseHmac<D : Any> : HMAC {
    // resolves the digest into the provider-native representation, fails if the digest is not supported
    protected abstract fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): D
    protected abstract fun blockSize(digest: D): Int
    protected abstract fun wrapKey(digest: CryptographyAlgorithmId<Digest>, resolvedDigest: D, rawKey: ByteArray): HMAC.Key

    final override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<HMAC.Key.Format, HMAC.Key> =
        BaseKeyDecoder(digest, resolveDigest(digest))

    final override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> =
        BaseKeyGenerator(digest, resolveDigest(digest))

    private inner class BaseKeyDecoder(
        private val digest: CryptographyAlgorithmId<Digest>,
        private val resolvedDigest: D,
    ) : Decoder<HMAC.Key.Format, HMAC.Key> {
        override fun decodeFromByteArrayBlocking(format: HMAC.Key.Format, bytes: ByteArray): HMAC.Key {
            val rawKey = when (format) {
                HMAC.Key.Format.RAW -> bytes.copyOf()
                HMAC.Key.Format.JWK -> JsonWebKeys.decodeHmacKey(digest, bytes)
            }
            return wrapKey(digest, resolvedDigest, rawKey)
        }
    }

    private inner class BaseKeyGenerator(
        private val digest: CryptographyAlgorithmId<Digest>,
        private val resolvedDigest: D,
    ) : KeyGenerator<HMAC.Key> {
        override fun generateKeyBlocking(): HMAC.Key {
            val key = CryptographySystem.getDefaultRandom().nextBytes(blockSize(resolvedDigest))
            return wrapKey(digest, resolvedDigest, key)
        }
    }

    protected abstract inner class BaseKey(
        private val digest: CryptographyAlgorithmId<Digest>,
        protected val key: ByteArray,
    ) : HMAC.Key {
        final override fun encodeToByteArrayBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
            HMAC.Key.Format.RAW -> key.copyOf()
            HMAC.Key.Format.JWK -> JsonWebKeys.encodeHmacKey(digest, key)
        }
    }
}
