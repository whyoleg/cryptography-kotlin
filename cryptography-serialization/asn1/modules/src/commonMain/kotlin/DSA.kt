/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.BigInt
import kotlinx.serialization.Serializable

@Serializable
public class DsaSignatureValue(
    public val r: BigInt,
    public val s: BigInt,
)