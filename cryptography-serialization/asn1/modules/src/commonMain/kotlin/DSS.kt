/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import kotlinx.serialization.*

@Serializable
public class DssSignatureValue(
    public val r: BigInt,
    public val s: BigInt,
)

@Deprecated(
    message = "Use DssSignatureValue instead",
    replaceWith = ReplaceWith(
        "DssSignatureValue",
        "dev.whyoleg.cryptography.serialization.asn1.modules.DssSignatureValue"
    ),
    level = DeprecationLevel.ERROR
)
public typealias EcdsaSignatureValue = DssSignatureValue
