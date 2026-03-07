/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

/**
 * OID for DSA algorithm (FIPS 186)
 * id-dsa OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4) 1 }
 */
public val ObjectIdentifier.Companion.DSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.10040.4.1")

/**
 * Algorithm identifier for DSA keys in SubjectPublicKeyInfo/PrivateKeyInfo.
 */
public class DsaAlgorithmIdentifier(
    override val parameters: DsaParameters?,
) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.DSA
}

/**
 * ```
 * DSAParameters ::= SEQUENCE {
 *   p INTEGER,
 *   q INTEGER,
 *   g INTEGER
 * }
 * ```
 *
 * As defined in FIPS 186 (RFC 3279).
 */
@Serializable
public class DsaParameters(
    public val prime: BigInt,
    public val subprime: BigInt,
    public val generator: BigInt,
)
