/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * Hash-based Message Authentication Code (HMAC)
 * as defined in [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
 *
 * HMAC computes and verifies message authentication codes using a secret key and a [Digest] algorithm.
 *
 * ```
 * val key = provider.get(HMAC).keyGenerator(SHA256).generateKey()
 * val signature = key.signatureGenerator().generateSignature(data)
 * key.signatureVerifier().verifySignature(data, signature)
 * ```
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<HMAC>("HMAC")

    /**
     * Returns a [Decoder] that decodes HMAC keys for the given [digest]
     * from the specified [Key.Format].
     */
    public fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<Key.Format, Key>

    /**
     * Returns a [KeyGenerator] that generates HMAC keys for the given [digest].
     */
    public fun keyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key>

    /**
     * An HMAC key that provides MAC computation via [signatureGenerator]
     * and verification via [signatureVerifier].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        /**
         * Returns a [SignatureGenerator] that computes message authentication codes.
         */
        public fun signatureGenerator(): SignatureGenerator

        /**
         * Returns a [SignatureVerifier] that verifies message authentication codes.
         */
        public fun signatureVerifier(): SignatureVerifier

        /**
         * Encoding formats for HMAC keys.
         */
        public enum class Format : EncodingFormat {
            /**
             * Raw key bytes.
             */
            RAW,

            /**
             * JSON Web Key format
             * as defined in [RFC 7518 Section 6.4](https://datatracker.ietf.org/doc/html/rfc7518#section-6.4).
             */
            JWK,
        }
    }
}
