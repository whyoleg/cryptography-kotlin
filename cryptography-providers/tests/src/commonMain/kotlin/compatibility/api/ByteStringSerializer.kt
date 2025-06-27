/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.jvm.*

typealias SerializableByteString = @Serializable(ByteStringSerializer::class) ByteString

@Serializable
@JvmInline
private value class ByteStringWrapper(val value: ByteArray)

@OptIn(UnsafeByteStringApi::class)
internal object ByteStringSerializer : KSerializer<ByteString> {
    private val delegate get() = ByteStringWrapper.serializer()

    override val descriptor: SerialDescriptor get() = delegate.descriptor

    override fun deserialize(decoder: Decoder): ByteString {
        return UnsafeByteStringOperations.wrapUnsafe(delegate.deserialize(decoder).value)
    }

    override fun serialize(encoder: Encoder, value: ByteString) {
        UnsafeByteStringOperations.withByteArrayUnsafe(value) {
            delegate.serialize(encoder, ByteStringWrapper(it))
        }
    }
}
