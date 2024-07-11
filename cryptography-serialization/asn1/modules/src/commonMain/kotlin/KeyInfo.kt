/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
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
    public val algorithm: KeyAlgorithmIdentifier,
    public val subjectPublicKey: BitArray,
)

/**
 * ```
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                            Version,
 *   privateKeyAlgorithm                PrivateKeyAlgorithmIdentifier,
 *   privateKey                         PrivateKey,
 *   attributes           [0] IMPLICIT  Attributes OPTIONAL
 * }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
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
    public val privateKeyAlgorithm: KeyAlgorithmIdentifier,
    public val privateKey: ByteArray,
)
