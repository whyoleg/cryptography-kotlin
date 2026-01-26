/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.ContextSpecificTag.*
import kotlinx.serialization.*

/**
 * ```
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm        AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 * ```
 */
@Serializable
public class SubjectPublicKeyInfo(
    @Contextual
    public val algorithm: AlgorithmIdentifier,
    public val subjectPublicKey: BitArray,
)

/**
 * OneAsymmetricKey as defined in RFC 5958 (extends PKCS#8 PrivateKeyInfo):
 * ```
 * OneAsymmetricKey ::= SEQUENCE {
 *   version                            Version,
 *   privateKeyAlgorithm                PrivateKeyAlgorithmIdentifier,
 *   privateKey                         PrivateKey,
 *   attributes           [0] IMPLICIT  Attributes OPTIONAL,
 *   publicKey            [1] IMPLICIT  PublicKey OPTIONAL
 * }
 *
 * Version ::= INTEGER { v1(0), v2(1) }
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * PublicKey ::= BIT STRING
 * ```
 *
 * `Attributes` is not yet supported:
 * ```
 * Attributes ::= SET OF Attribute
 * Attribute ::= SEQUENCE {
 *   type   OBJECT IDENTIFIER,
 *   values AttributeSetValue
 * }
 * AttributeSetValue ::= SET OF ANY
 * ```
 */
@Serializable
public class PrivateKeyInfo(
    public val version: Int,
    @Contextual
    public val privateKeyAlgorithm: AlgorithmIdentifier,
    public val privateKey: ByteArray,
    @ContextSpecificTag(1, TagType.IMPLICIT)
    public val publicKey: BitArray? = null,
)
