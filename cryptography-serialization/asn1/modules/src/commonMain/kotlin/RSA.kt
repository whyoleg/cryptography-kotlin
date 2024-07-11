/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

public val ObjectIdentifier.Companion.RSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1")

public object RsaKeyAlgorithmIdentifier : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA
    override val parameters: Nothing? get() = null
}

/**
 * ```
 * RSAPublicKey ::= SEQUENCE {
 *   modulus        INTEGER,    -- n
 *   publicExponent INTEGER     -- e
 * }
 * ```
 */
@Serializable
public class RsaPublicKey(
    public val modulus: BigInt,
    public val publicExponent: BigInt,
)

/**
 * ```
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER,  -- e
 *   privateExponent   INTEGER,  -- d
 *   prime1            INTEGER,  -- p
 *   prime2            INTEGER,  -- q
 *   exponent1         INTEGER,  -- d mod (p-1)
 *   exponent2         INTEGER,  -- d mod (q-1)
 *   coefficient       INTEGER,  -- (inverse of q) mod p
 *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * ```
 *
 * `OtherPrimeInfos` is not supported yet:
 * ```
 * OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
 *
 * OtherPrimeInfo ::= SEQUENCE {
 *     prime             INTEGER,  -- ri
 *     exponent          INTEGER,  -- di
 *     coefficient       INTEGER   -- ti
 * }
 * ```
 */
@Serializable
public class RsaPrivateKey(
    public val version: Int,
    public val modulus: BigInt,
    public val publicExponent: BigInt,
    public val privateExponent: BigInt,
    public val prime1: BigInt,
    public val prime2: BigInt,
    public val exponent1: BigInt,
    public val exponent2: BigInt,
    public val coefficient: BigInt,
)
