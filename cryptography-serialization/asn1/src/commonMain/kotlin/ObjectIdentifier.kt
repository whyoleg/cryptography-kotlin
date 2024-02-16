/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*
import kotlin.jvm.*

@Serializable
@JvmInline
public value class ObjectIdentifier(public val value: String) {
    public companion object
}
