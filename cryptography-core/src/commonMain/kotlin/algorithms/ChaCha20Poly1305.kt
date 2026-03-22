/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * ChaCha20-Poly1305 authenticated encryption with associated data (AEAD)
 * as defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
 *
 * ChaCha20-Poly1305 combines the ChaCha20 stream cipher with the Poly1305 message authentication code
 * to provide both confidentiality and integrity.
 * Uses 256-bit keys, 96-bit (12-byte) nonce, and a 128-bit (16-byte) authentication tag.
 *
 * A good alternative to [AES.GCM] on platforms without hardware AES acceleration (AES-NI),
 * as ChaCha20 performs well in pure software implementations.
 *
 * ```
 * val key = provider.get(ChaCha20Poly1305).keyGenerator().generateKey()
 * val ciphertext = key.cipher().encrypt(plaintext)
 * ```
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ChaCha20Poly1305 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<ChaCha20Poly1305> get() = Companion

    public companion object : CryptographyAlgorithmId<ChaCha20Poly1305>("ChaCha20-Poly1305")

    /**
     * Returns a [Decoder] that decodes ChaCha20-Poly1305 keys from the specified [Key.Format].
     */
    public fun keyDecoder(): Decoder<Key.Format, Key>

    /**
     * Returns a [KeyGenerator] that generates ChaCha20-Poly1305 keys.
     */
    public fun keyGenerator(): KeyGenerator<Key>

    /**
     * A ChaCha20-Poly1305 key that provides authenticated encryption and decryption via [cipher].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        /**
         * Returns an [IvAuthenticatedCipher] for authenticated encryption and decryption.
         */
        public fun cipher(): IvAuthenticatedCipher

        /**
         * Encoding formats for ChaCha20-Poly1305 keys.
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
