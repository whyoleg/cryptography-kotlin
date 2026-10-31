/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

typealias SerializableByteString = @Serializable(ByteStringSerializer::class) ByteString

internal object ByteStringSerializer : KSerializer<ByteString> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ByteString", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteString {
        return decoder.decodeString().hexToByteString()
    }

    override fun serialize(encoder: Encoder, value: ByteString) {
        encoder.encodeString(value.toHexString())
    }
}
