/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.modules.*

// TODO: use AbstractEncoder
internal class DerEncoder(private val der: DER, private val output: DerOutput) : Encoder {
    override val serializersModule: SerializersModule
        get() = der.serializersModule

    @ExperimentalSerializationApi
    override fun encodeNotNullMark() {
        // TODO: do we need something here?
    }

    @ExperimentalSerializationApi
    override fun encodeNull(): Unit = output.writeNull()
    override fun encodeByte(value: Byte): Unit = output.writeInteger(value.toBigInt())
    override fun encodeShort(value: Short): Unit = output.writeInteger(value.toBigInt())
    override fun encodeInt(value: Int): Unit = output.writeInteger(value.toBigInt())
    override fun encodeLong(value: Long): Unit = output.writeInteger(value.toBigInt())

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) = when (serializer.descriptor) {
        // TODO: how this works?
        // TODO check BitString
        ByteArraySerializer().descriptor         -> output.writeOctetString(value as ByteArray)
        ObjectIdentifier.serializer().descriptor -> output.writeObjectIdentifier(value as ObjectIdentifier)
        BigInt.serializer().descriptor           -> output.writeInteger(value as BigInt)
        else                                     -> super.encodeSerializableValue(serializer, value)
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder = when (descriptor.kind) {
        StructureKind.CLASS,
        PolymorphicKind.OPEN,
        PolymorphicKind.SEALED,
             -> DerSequenceEncoder(der, output)
        else -> throw SerializationException("This serial kind is not supported as structure: $descriptor")
    }

    override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int): CompositeEncoder {
        // SEQUENCE OF
        error("Collections encoding is not supported")
    }

    // this could be supported, but later
    override fun encodeInline(descriptor: SerialDescriptor): Encoder = error("Inline encoding is not supported")
    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = error("Enum encoding is not supported")

    // Strings could be supported, but later
    override fun encodeString(value: String): Unit = error("String encoding is not supported")

    // TBD what to do here
    override fun encodeChar(value: Char): Unit = error("Char encoding is not supported")
    override fun encodeBoolean(value: Boolean): Unit = error("Boolean encoding is not supported")
    override fun encodeFloat(value: Float): Unit = error("Float encoding is not supported")
    override fun encodeDouble(value: Double): Unit = error("Double encoding is not supported")
}

private class DerSequenceEncoder(
    private val der: DER,
    private val parentOutput: DerOutput,
) : CompositeEncoder {
    private val byteArrayOutput = ByteArrayOutput()
    private val output = DerOutput(byteArrayOutput)
    private val encoder = DerEncoder(der, output)

    override val serializersModule: SerializersModule get() = der.serializersModule

    override fun endStructure(descriptor: SerialDescriptor): Unit = parentOutput.writeSequence(byteArrayOutput)

    override fun encodeByteElement(descriptor: SerialDescriptor, index: Int, value: Byte): Unit = encoder.encodeByte(value)
    override fun encodeShortElement(descriptor: SerialDescriptor, index: Int, value: Short): Unit = encoder.encodeShort(value)
    override fun encodeIntElement(descriptor: SerialDescriptor, index: Int, value: Int): Unit = encoder.encodeInt(value)
    override fun encodeLongElement(descriptor: SerialDescriptor, index: Int, value: Long): Unit = encoder.encodeLong(value)

    override fun encodeBooleanElement(descriptor: SerialDescriptor, index: Int, value: Boolean): Unit = encoder.encodeBoolean(value)
    override fun encodeFloatElement(descriptor: SerialDescriptor, index: Int, value: Float): Unit = encoder.encodeFloat(value)
    override fun encodeDoubleElement(descriptor: SerialDescriptor, index: Int, value: Double): Unit = encoder.encodeDouble(value)

    override fun encodeCharElement(descriptor: SerialDescriptor, index: Int, value: Char): Unit = encoder.encodeChar(value)
    override fun encodeStringElement(descriptor: SerialDescriptor, index: Int, value: String): Unit = encoder.encodeString(value)

    override fun encodeInlineElement(descriptor: SerialDescriptor, index: Int): Encoder = error("Inline encoding is not supported")

    @OptIn(ExperimentalSerializationApi::class)
    override fun <T> encodeSerializableElement(
        descriptor: SerialDescriptor,
        index: Int,
        serializer: SerializationStrategy<T>,
        value: T,
    ) {
        if (
            descriptor.getElementDescriptor(index) == ByteArraySerializer().descriptor &&
            descriptor.getElementAnnotations(index).any { it is Asn1BitString }
        ) {
            output.writeBitString(value as ByteArray)
        } else {
            encoder.encodeSerializableValue(serializer, value)
        }
    }

    @ExperimentalSerializationApi
    override fun <T : Any> encodeNullableSerializableElement(
        descriptor: SerialDescriptor,
        index: Int,
        serializer: SerializationStrategy<T>,
        value: T?,
    ): Unit = encoder.encodeNullableSerializableValue(serializer, value)

    @ExperimentalSerializationApi
    override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean = false // TODO
}
