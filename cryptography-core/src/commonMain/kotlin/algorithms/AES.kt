/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * Advanced Encryption Standard (AES) symmetric encryption algorithm
 * as defined in [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
 *
 * AES supports multiple modes of operation:
 * * [GCM] and [CCM] — authenticated encryption with associated data (AEAD).
 * * [CTR], [CBC], [OFB], [CFB], [CFB8] — unauthenticated block/stream cipher modes.
 * * [ECB] — electronic codebook, unsuitable for most use cases.
 * * [CMAC] — message authentication code.
 *
 * Key sizes of 128, 192, or 256 bits are available via [Key.Size].
 * For authenticated encryption, prefer [GCM]. For legacy compatibility, [CBC] is widely supported.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    /**
     * Returns a [Decoder] that decodes AES keys from the specified [Key.Format].
     */
    public fun keyDecoder(): Decoder<Key.Format, K>

    /**
     * Returns a [KeyGenerator] that generates AES keys of the given [keySize].
     */
    public fun keyGenerator(keySize: BinarySize = Key.Size.B256): KeyGenerator<K>

    @Suppress("DEPRECATION_ERROR")
    @Deprecated(
        "Replaced by overload with BinarySize",
        ReplaceWith("keyGenerator(keySize.value)"),
        DeprecationLevel.ERROR
    )
    public fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<K> = keyGenerator(keySize.value)

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        /**
         * Encoding formats for AES keys.
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

        /**
         * Standard AES key sizes.
         */
        public object Size {
            public val B128: BinarySize get() = 128.bits
            public val B192: BinarySize get() = 192.bits
            public val B256: BinarySize get() = 256.bits
        }
    }

    /**
     * AES in Galois/Counter Mode (GCM), an authenticated encryption scheme
     * as defined in [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
     *
     * Provides confidentiality and authenticity with support for associated data.
     * Uses a 96-bit (12-byte) IV by default.
     *
     * ```
     * val key = provider.get(AES.GCM).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface GCM : AES<GCM.Key> {
        override val id: CryptographyAlgorithmId<GCM> get() = Companion

        public companion object : CryptographyAlgorithmId<GCM>("AES-GCM")

        /**
         * An AES-GCM key that provides authenticated encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvAuthenticatedCipher] for encryption and decryption
             * with an authentication tag of the given [tagSize].
             *
             * Supported tag sizes are 96, 104, 112, 120, and 128 bits.
             * The default 128 bits provides maximum forgery resistance; smaller tags save space but reduce security.
             */
            public fun cipher(tagSize: BinarySize = 128.bits): IvAuthenticatedCipher
        }
    }

    /**
     * AES in Counter with CBC-MAC (CCM) mode, an authenticated encryption scheme
     * as defined in [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final).
     *
     * Provides confidentiality and authenticity with support for associated data.
     * Uses a 96-bit (12-byte) nonce by default.
     *
     * ```
     * val key = provider.get(AES.CCM).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CCM : AES<CCM.Key> {
        override val id: CryptographyAlgorithmId<CCM> get() = Companion

        public companion object : CryptographyAlgorithmId<CCM>("AES-CCM")

        /**
         * An AES-CCM key that provides authenticated encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvAuthenticatedCipher] for encryption and decryption
             * with an authentication tag of the given [tagSize].
             *
             * Supported tag sizes are 32, 48, 64, 80, 96, 112, and 128 bits.
             */
            public fun cipher(tagSize: BinarySize = 128.bits): IvAuthenticatedCipher
        }
    }

    /**
     * AES in Counter (CTR) mode, a stream cipher
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Turns AES into a stream cipher by encrypting successive counter-blocks.
     * Uses a 128-bit (16-byte) IV by default.
     * Does not provide authentication — use [GCM] when integrity is required.
     *
     * ```
     * val key = provider.get(AES.CTR).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CTR : AES<CTR.Key> {
        override val id: CryptographyAlgorithmId<CTR> get() = Companion

        public companion object : CryptographyAlgorithmId<CTR>("AES-CTR")

        /**
         * An AES-CTR key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvCipher] for encryption and decryption.
             */
            public fun cipher(): IvCipher
        }
    }

    /**
     * AES in Cipher Block Chaining (CBC) mode
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Each plaintext block is XORed with the previous ciphertext block before encryption.
     * Uses a 128-bit (16-byte) IV by default.
     * Does not provide authentication — use [GCM] when integrity is required.
     *
     * ```
     * val key = provider.get(AES.CBC).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CBC : AES<CBC.Key> {
        override val id: CryptographyAlgorithmId<CBC> get() = Companion

        public companion object : CryptographyAlgorithmId<CBC>("AES-CBC")

        /**
         * An AES-CBC key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvCipher] for encryption and decryption with PKCS#7 [padding] enabled or disabled.
             *
             * When padding is disabled, the plaintext must be a multiple of 16 bytes (AES block size).
             */
            public fun cipher(padding: Boolean = true): IvCipher
        }
    }

    /**
     * AES Cipher-based Message Authentication Code (CMAC)
     * as defined in [NIST SP 800-38B](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final).
     *
     * Computes and verifies authentication tags using AES as the underlying block cipher.
     *
     * ```
     * val key = provider.get(AES.CMAC).keyGenerator().generateKey()
     * val tag = key.signatureGenerator().generateSignature(data)
     * key.signatureVerifier().verifySignature(data, tag)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CMAC : AES<CMAC.Key> {
        override val id: CryptographyAlgorithmId<CMAC> get() = Companion

        public companion object : CryptographyAlgorithmId<CMAC>("AES-CMAC")

        /**
         * An AES-CMAC key that provides MAC computation via [signatureGenerator] and verification via [signatureVerifier].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns a [SignatureGenerator] that computes message authentication codes.
             */
            public fun signatureGenerator(): SignatureGenerator

            /**
             * Returns a [SignatureVerifier] that verifies message authentication codes.
             */
            public fun signatureVerifier(): SignatureVerifier
        }
    }

    /**
     * AES in Electronic Codebook (ECB) mode
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Encrypts each block independently **without** an initialization vector.
     * Identical plaintext blocks produce identical ciphertext blocks, making this mode
     * unsuitable for most use cases except for legacy compatibility.
     *
     * ```
     * val key = provider.get(AES.ECB).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface ECB : AES<ECB.Key> {
        override val id: CryptographyAlgorithmId<ECB> get() = Companion

        public companion object : CryptographyAlgorithmId<ECB>("AES-ECB")

        /**
         * An AES-ECB key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns a [Cipher] for encryption and decryption with PKCS#7 [padding] enabled or disabled.
             *
             * When padding is disabled, the plaintext must be a multiple of 16 bytes (AES block size).
             */
            public fun cipher(padding: Boolean = true): Cipher
        }
    }

    /**
     * AES in Output Feedback (OFB) mode, a stream cipher
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Turns AES into a stream cipher by repeatedly encrypting the previous output block.
     * Uses a 128-bit (16-byte) IV by default.
     * Does not provide authentication — use [GCM] when integrity is required.
     *
     * ```
     * val key = provider.get(AES.OFB).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface OFB : AES<OFB.Key> {
        override val id: CryptographyAlgorithmId<OFB> get() = Companion

        public companion object : CryptographyAlgorithmId<OFB>("AES-OFB")

        /**
         * An AES-OFB key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvCipher] for encryption and decryption.
             */
            public fun cipher(): IvCipher
        }
    }

    /**
     * AES in Cipher Feedback (CFB) mode with full-block feedback, a stream cipher
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Turns AES into a self-synchronizing stream cipher using full-block (128-bit) feedback.
     * Uses a 128-bit (16-byte) IV by default.
     * Does not provide authentication — use [GCM] when integrity is required.
     *
     * ```
     * val key = provider.get(AES.CFB).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CFB : AES<CFB.Key> {
        override val id: CryptographyAlgorithmId<CFB> get() = Companion

        public companion object : CryptographyAlgorithmId<CFB>("AES-CFB")

        /**
         * An AES-CFB key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvCipher] for encryption and decryption.
             */
            public fun cipher(): IvCipher
        }
    }

    /**
     * AES in Cipher Feedback (CFB8) mode with 8-bit feedback
     * as defined in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
     *
     * Variant of [CFB] that uses 8-bit (1-byte) feedback segments instead of full blocks.
     * Uses a 128-bit (16-byte) IV by default.
     * Does not provide authentication — use [GCM] when integrity is required.
     *
     * ```
     * val key = provider.get(AES.CFB8).keyGenerator().generateKey()
     * val ciphertext = key.cipher().encrypt(plaintext)
     * ```
     */
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CFB8 : AES<CFB8.Key> {
        override val id: CryptographyAlgorithmId<CFB8> get() = Companion

        public companion object : CryptographyAlgorithmId<CFB8>("AES-CFB8")

        /**
         * An AES-CFB8 key that provides encryption and decryption via [cipher].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            /**
             * Returns an [IvCipher] for encryption and decryption.
             */
            public fun cipher(): IvCipher
        }
    }
}
