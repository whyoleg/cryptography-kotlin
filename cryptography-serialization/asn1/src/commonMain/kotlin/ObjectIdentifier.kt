/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*
import kotlin.jvm.*

@Serializable
@JvmInline
public value class ObjectIdentifier(public val value: String) {
    public companion object {
        public inline val RSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1")
        public inline val RSA_PSS: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1") // TODO
        public inline val RSA_OAEP: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.7") // TODO
    }
}
