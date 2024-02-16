/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.serialization.*
import kotlinx.serialization.modules.*

public sealed class DER(
    override val serializersModule: SerializersModule,
) : BinaryFormat {

    public companion object Default : DER(
        serializersModule = EmptySerializersModule()
    )

    override fun <T> encodeToByteArray(serializer: SerializationStrategy<T>, value: T): ByteArray {
        val output = ByteArrayOutput()
        DerEncoder(this, output).encodeSerializableValue(serializer, value)
        return output.toByteArray()
    }

    override fun <T> decodeFromByteArray(deserializer: DeserializationStrategy<T>, bytes: ByteArray): T {
        val input = ByteArrayInput(bytes)
        return DerDecoder(this, input).decodeSerializableValue(deserializer)
    }

    public class Builder internal constructor(der: DER) {
        public var serializersModule: SerializersModule = der.serializersModule
    }
}

public fun DER(from: DER = DER.Default, builderAction: DER.Builder.() -> Unit): DER {
    return DerImpl(DER.Builder(from).apply(builderAction))
}

private class DerImpl(builder: Builder) : DER(
    serializersModule = builder.serializersModule
)
