/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

public object BigIntAsStringSerializer : KSerializer<BigInt> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("BigInt", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: BigInt) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): BigInt {
        return decoder.decodeString().toBigInt()
    }
}

public object BigIntAsByteArraySerializer : KSerializer<BigInt> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("BigInt", ByteArraySerializer().descriptor)

    override fun serialize(encoder: Encoder, value: BigInt) {
        encoder.encodeSerializableValue(ByteArraySerializer(), value.encodeToByteArray())
    }

    override fun deserialize(decoder: Decoder): BigInt {
        return decoder.decodeSerializableValue(ByteArraySerializer()).decodeToBigInt()
    }
}
