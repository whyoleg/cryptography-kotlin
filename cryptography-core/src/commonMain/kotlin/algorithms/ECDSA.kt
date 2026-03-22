/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA)
 * as defined in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
 *
 * ECDSA provides digital signature generation and verification using elliptic curve keys.
 * The [EC.Curve] is selected when creating key decoders or generators via the inherited [EC] methods.
 *
 * ```
 * val keys = provider.get(ECDSA).keyPairGenerator(EC.Curve.P256).generateKey()
 * val signature = keys.privateKey.signatureGenerator(SHA256, ECDSA.SignatureFormat.DER).generateSignature(data)
 * keys.publicKey.signatureVerifier(SHA256, ECDSA.SignatureFormat.DER).verifySignature(data, signature)
 * ```
 *
 * For signatures using Edwards curves, see [EdDSA].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDSA : EC<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDSA>("ECDSA")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    /**
     * An ECDSA public key that provides signature verification via [signatureVerifier].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        /**
         * Returns a [SignatureVerifier] that verifies signatures using the specified [digest] and [format].
         * Pass `null` for [digest] when verifying pre-hashed data.
         */
        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureVerifier
    }

    /**
     * An ECDSA private key that provides signature generation via [signatureGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey<PublicKey> {
        /**
         * Returns a [SignatureGenerator] that generates signatures using the specified [digest] and [format].
         * Pass `null` for [digest] when signing pre-hashed data.
         */
        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureGenerator
    }

    /**
     * Encoding format for ECDSA signatures.
     */
    public enum class SignatureFormat {
        /**
         * IEEE P1363 format: fixed-length concatenation of `r || s`.
         *
         * Each value is zero-padded to the curve's field size.
         * Defined in IEEE P1363 and also described in
         * [RFC 7518 Section 3.4](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).
         */
        RAW,

        /**
         * ASN.1 DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`.
         *
         * Variable length.
         * Defined in [RFC 3279 Section 2.2.3](https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3).
         */
        DER
    }
}
