/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

internal enum class DerTag(val value: Byte) {
    INTEGER(0x02),
    BIT_STRING(0x03),
    OCTET_STRING(0x04),
    NULL(0x05),
    OID(0x06),
    SEQUENCE(0x30),
}
