/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*

internal typealias DerTag = Byte

internal const val DerTag_INTEGER: DerTag = 0x02
internal const val DerTag_BIT_STRING: DerTag = 0x03
internal const val DerTag_OCTET_STRING: DerTag = 0x04
internal const val DerTag_NULL: DerTag = 0x05
internal const val DerTag_OID: DerTag = 0x06
internal const val DerTag_SEQUENCE: DerTag = 0x30

private const val DerTag_CLASS_CONTEXT_SPECIFIC: Int = 0b10000000
private const val DerTag_FORM_CONSTRUCTED: Int = 0b00100000

@Suppress("FunctionName")
internal fun DerTag_name(tag: DerTag): String = when (tag) {
    DerTag_INTEGER      -> "INTEGER"
    DerTag_BIT_STRING   -> "BIT_STRING"
    DerTag_OCTET_STRING -> "OCTET_STRING"
    DerTag_NULL         -> "NULL"
    DerTag_OID          -> "OID"
    DerTag_SEQUENCE     -> "SEQUENCE"
    else -> {
        val intTag = tag.toInt()
        if (intTag.hasFlag(DerTag_CLASS_CONTEXT_SPECIFIC)) {
            if (intTag.hasFlag(DerTag_FORM_CONSTRUCTED)) {
                "CONTEXT_SPECIFIC:EXPLICIT[${(intTag - DerTag_CLASS_CONTEXT_SPECIFIC - DerTag_FORM_CONSTRUCTED).toUByte()}]"
            } else {
                "CONTEXT_SPECIFIC:IMPLICIT[${(intTag - DerTag_CLASS_CONTEXT_SPECIFIC).toUByte()}]"
            }
        } else {
            "UNKNOWN[0x${tag.toUByte().toString(16)}]"
        }
    }
}

@ExperimentalSerializationApi
internal fun SerialDescriptor.getElementContextSpecificTag(index: Int): ContextSpecificTag? {
    val annotation = getElementAnnotations(index).firstOrNull { it is ContextSpecificTag } as? ContextSpecificTag ?: return null
    check(annotation.classIndex < 31) { "Context specific tag class must be less than 31, but was ${annotation.classIndex}" }
    return annotation
}

internal val ContextSpecificTag.tag: DerTag
    get() {
        val contextSpecificTag = classIndex.toInt() or DerTag_CLASS_CONTEXT_SPECIFIC
        return when (type) {
            ContextSpecificTag.TagType.IMPLICIT -> contextSpecificTag.toByte()
            ContextSpecificTag.TagType.EXPLICIT -> (contextSpecificTag or DerTag_FORM_CONSTRUCTED).toByte()
        }
    }

private fun Int.hasFlag(flag: Int): Boolean = (this and flag) == flag
