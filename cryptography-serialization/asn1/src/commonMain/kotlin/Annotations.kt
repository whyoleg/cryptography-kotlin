/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*

@Target(AnnotationTarget.PROPERTY)
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
public annotation class ContextSpecificTag(
    public val classIndex: Byte,
    public val type: TagType,
) {
    public enum class TagType { IMPLICIT, EXPLICIT }
}
