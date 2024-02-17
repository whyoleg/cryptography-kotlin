/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*

@Serializable
public class BitArray(
    public val unusedBits: Int,
    public val byteArray: ByteArray,
) {
    // TODO: validate
}
