/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*
import kotlin.jvm.*

@Serializable
@JvmInline
public value class ObjectIdentifier(public val value: String) {
    public companion object
}

@Serializable // TODO: what should be the default way? asn.1 bytearray? string?
@JvmInline
public class ObjectIdentifier2 private constructor(

) {
    public val nodes: IntArray get() = TODO()
    public fun toByteArray(): ByteArray = TODO()

    override fun toString(): String = TODO()

    public companion object {
        // TODO: have a cache here?

        // 1.1.1.1.1
        public fun parse(value: String): ObjectIdentifier2 = TODO()

        public fun fromByteArray(bytes: ByteArray): ObjectIdentifier2 = TODO()
        public fun fromNodes(vararg nodes: Int): ObjectIdentifier2 = TODO()
    }
}
