/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

internal typealias DerTag = Byte

internal const val DerTag_INTEGER: DerTag = 0x02
internal const val DerTag_BIT_STRING: DerTag = 0x03
internal const val DerTag_OCTET_STRING: DerTag = 0x04
internal const val DerTag_NULL: DerTag = 0x05
internal const val DerTag_OID: DerTag = 0x06
internal const val DerTag_SEQUENCE: DerTag = 0x30

internal fun name(tag: DerTag): String = when (tag) {
    DerTag_INTEGER      -> "INTEGER"
    DerTag_BIT_STRING   -> "BIT_STRING"
    DerTag_OCTET_STRING -> "OCTET_STRING"
    DerTag_NULL         -> "NULL"
    DerTag_OID          -> "OID"
    DerTag_SEQUENCE     -> "SEQUENCE"
    else                -> "UNKNOWN[$tag]"
}
