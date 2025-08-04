/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.io.*
import kotlinx.serialization.*

public fun <T> Der.encodeToSink(
    serializer: SerializationStrategy<T>,
    value: T,
    sink: Sink,
) {
    DerEncoder(this, SinkOutput(sink))
        .encodeSerializableValue(serializer, value)
}

public inline fun <reified T> Der.encodeToSink(value: T, sink: Sink): Unit = encodeToSink(serializersModule.serializer(), value, sink)

public fun <T> Der.decodeFromSource(
    deserializer: DeserializationStrategy<T>,
    source: Source,
): T {
    return DerDecoder(this, SourceInput(source)).decodeSerializableValue(deserializer)
}

public inline fun <reified T> Der.decodeFromSource(source: Source): T = decodeFromSource(serializersModule.serializer(), source)
