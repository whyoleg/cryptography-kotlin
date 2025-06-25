/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.io.encoding.*

typealias ByteStringAsString = @Serializable(ByteStringAsStringSerializer::class) ByteString

internal object ByteStringAsStringSerializer : KSerializer<ByteString> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ByteString#Base64", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder): ByteString = Base64.decodeToByteString(decoder.decodeString())
    override fun serialize(encoder: Encoder, value: ByteString): Unit = encoder.encodeString(Base64.encode(value))
}
