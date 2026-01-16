/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*

/**
 * ```
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm  OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 * ```
 */
@Serializable(DefaultAlgorithmIdentifierSerializer::class)
public interface AlgorithmIdentifier {
    public val algorithm: ObjectIdentifier
    public val parameters: Any?
}

