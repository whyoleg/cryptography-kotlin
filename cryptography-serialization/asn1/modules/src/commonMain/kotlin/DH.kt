/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

/**
 * OID for DH key agreement algorithm (PKCS#3)
 * id-dhKeyAgreement OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-3(3) 1 }
 */
public val ObjectIdentifier.Companion.DH: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.3.1")

/**
 * Algorithm identifier for DH keys in SubjectPublicKeyInfo/PrivateKeyInfo.
 */
public class DhAlgorithmIdentifier(
    override val parameters: DhParameters?,
) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.DH
}

/**
 * ```
 * DHParameter ::= SEQUENCE {
 *   prime           INTEGER,  -- p
 *   base            INTEGER,  -- g
 *   privateValueLength INTEGER OPTIONAL
 * }
 * ```
 *
 * As defined in PKCS#3 (RFC 2631).
 * The privateValueLength field is optional and typically omitted.
 */
@Serializable
public class DhParameters(
    public val prime: BigInt,
    public val base: BigInt,
    public val privateValueLength: Int? = null,
)
