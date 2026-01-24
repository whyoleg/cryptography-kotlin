/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.ContextSpecificTag.*
import kotlinx.serialization.*
import kotlin.jvm.*

public val ObjectIdentifier.Companion.EC: ObjectIdentifier get() = ObjectIdentifier("1.2.840.10045.2.1")

public class EcAlgorithmIdentifier(
    override val parameters: EcParameters?,
) : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.EC
}

@Deprecated(
    message = "Use EcAlgorithmIdentifier instead",
    replaceWith = ReplaceWith(
        "EcAlgorithmIdentifier",
        "dev.whyoleg.cryptography.serialization.asn1.modules.EcAlgorithmIdentifier"
    ),
    level = DeprecationLevel.ERROR
)
public typealias EcKeyAlgorithmIdentifier = EcAlgorithmIdentifier

/**
 * ```
 * ECPoint ::= OCTET STRING
 * ```
 *
 * This is EC `publicKey` representation for SubjectPublicKeyInfo
 */
@Serializable
@JvmInline
public value class EcPoint(
    public val bytes: ByteArray,
)

/**
 * ```
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * ```
 */
@Serializable
public class EcPrivateKey(
    public val version: Int,
    public val privateKey: ByteArray,
    @ContextSpecificTag(0, TagType.EXPLICIT)
    public val parameters: EcParameters? = null,
    @ContextSpecificTag(1, TagType.EXPLICIT)
    public val publicKey: BitArray? = null,
)

/**
 * ```
 * ECParameters ::= CHOICE {
 *   namedCurve        OBJECT IDENTIFIER
 *   -- implicitCurve  NULL
 *   -- specifiedCurve SpecifiedECDomain
 * }
 * ```
 *
 * Overall while it's `CHOICE` in ASN.1, but only `namedCurve` is allowed
 */
@Serializable
@JvmInline
public value class EcParameters(
    public val namedCurve: ObjectIdentifier,
)

public val ObjectIdentifier.Companion.secp256r1: ObjectIdentifier get() = ObjectIdentifier("1.2.840.10045.3.1.7")
public val ObjectIdentifier.Companion.secp384r1: ObjectIdentifier get() = ObjectIdentifier("1.3.132.0.34")
public val ObjectIdentifier.Companion.secp521r1: ObjectIdentifier get() = ObjectIdentifier("1.3.132.0.35")

/**
 * ```
 * Ecdsa-Sig-Value ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 * ```
 */
@Serializable
public class EcdsaSignatureValue(
    public val r: BigInt,
    public val s: BigInt,
)
