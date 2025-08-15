/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.internal.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
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

@Deprecated("Renamed to Der", ReplaceWith("Der(from, builderAction)"), DeprecationLevel.ERROR)
public fun DER(from: Der = Der.Default, builderAction: Der.Builder.() -> Unit): Der {
    return Der(from, builderAction)
}

public fun Der(from: Der = Der.Default, builderAction: Der.Builder.() -> Unit): Der {
    return DerImpl(Der.Builder(from).apply(builderAction))
}

private class DerImpl(builder: Builder) : Der(
    serializersModule = builder.serializersModule
)

@OptIn(UnsafeByteStringApi::class)
public fun <T> Der.encodeToByteString(serializer: SerializationStrategy<T>, value: T): ByteString {
    return UnsafeByteStringOperations.wrapUnsafe(encodeToByteArray(serializer, value))
}

@OptIn(UnsafeByteStringApi::class)
public fun <T> Der.decodeFromByteString(deserializer: DeserializationStrategy<T>, bytes: ByteString): T {
    UnsafeByteStringOperations.withByteArrayUnsafe(bytes) {
        return decodeFromByteArray(deserializer, it)
    }
}

public fun <T> Der.encodeToSink(serializer: SerializationStrategy<T>, value: T, sink: Sink) {

}

public fun <T> Der.decodeFromSource(deserializer: DeserializationStrategy<T>, source: Source): T {
    TODO()
}

public inline fun <reified T> Der.encodeToByteString(value: T): ByteString = encodeToByteString(serializersModule.serializer(), value)

public inline fun <reified T> Der.decodeFromByteString(bytes: ByteString): T = decodeFromByteString(serializersModule.serializer(), bytes)

public inline fun <reified T> Der.encodeToSink(value: T, sink: Sink): Unit = encodeToSink(serializersModule.serializer(), value, sink)

public inline fun <reified T> Der.decodeFromSource(source: Source): T = decodeFromSource(serializersModule.serializer(), source)

// internals
//internal sealed class BinaryOutput {
//    abstract fun write(byte: Byte)
//    fun write(byte: Int): Unit = write(byte.toByte())
//    abstract fun write(bytes: ByteArray)
//    abstract fun write(output: BinaryOutput)
//    abstract fun newBinaryOutput(): BinaryOutput
//}
//
//internal class SinkOutput(
//    private val sink: Sink,
//    private val source: Source
//) : BinaryOutput() {
//    override fun write(byte: Byte) {
//        sink.writeByte(byte)
//    }
//
//    override fun write(bytes: ByteArray) {
//        sink.write(bytes)
//    }
//
//    override fun write(output: BinaryOutput) {
//        output as SinkOutput
//        output.sink.transferFrom(sink)
//    }
//
//    override fun newBinaryOutput(): BinaryOutput {
//        TODO("Not yet implemented")
//    }
//}
