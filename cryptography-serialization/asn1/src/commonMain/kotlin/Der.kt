/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.serialization.*
import kotlinx.serialization.modules.*

@Deprecated("Renamed to Der", ReplaceWith("Der"), DeprecationLevel.ERROR)
public typealias DER = Der

public sealed class Der(
    override val serializersModule: SerializersModule,
) : BinaryFormat {

    public companion object Default : Der(
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

    public class Builder internal constructor(der: Der) {
        public var serializersModule: SerializersModule = der.serializersModule
    }
}

public fun DER(from: Der = Der.Default, builderAction: Der.Builder.() -> Unit): Der {
    return DerImpl(Der.Builder(from).apply(builderAction))
}

private class DerImpl(builder: Builder) : Der(
    serializersModule = builder.serializersModule
)
