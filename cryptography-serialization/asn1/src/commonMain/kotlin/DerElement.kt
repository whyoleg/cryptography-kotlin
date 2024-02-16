/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.bigint.*

public sealed class DerElement

public object DerNull : DerElement()

public class DerInteger(
    public val value: BigInt,
) : DerElement()

public class DerObjectIdentifier(
    public val value: ObjectIdentifier,
) : DerElement()

public class DerBitString(
    public val value: ByteArray,
) : DerElement()

public class DerOctetString(
    public val value: ByteArray,
) : DerElement()

// not supported yet
//public class DerString(
//    public val value: String
//): DerElement()

public class DerSequence(
    private val content: List<DerElement>,
) : DerElement(), List<DerElement> by content
