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

@OptIn(ExperimentalSerializationApi::class)
internal open class DerEncoder(
    private val der: DER,
    byteArrayOutput: ByteArrayOutput,
) : AbstractEncoder() {
    private val output = DerOutput(byteArrayOutput)

    final override val serializersModule: SerializersModule get() = der.serializersModule

    final override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean = false // TODO

    final override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean = true

    final override fun encodeNotNullMark() {}
    final override fun encodeNull(): Unit = output.writeNull()
    final override fun encodeByte(value: Byte): Unit = output.writeInteger(value.toBigInt())
    final override fun encodeShort(value: Short): Unit = output.writeInteger(value.toBigInt())
    final override fun encodeInt(value: Int): Unit = output.writeInteger(value.toBigInt())
    final override fun encodeLong(value: Long): Unit = output.writeInteger(value.toBigInt())

    final override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T): Unit = when (serializer.descriptor) {
        // TODO: how this works?
        ByteArraySerializer().descriptor         -> output.writeOctetString(value as ByteArray)
        ObjectIdentifier.serializer().descriptor -> output.writeObjectIdentifier(value as ObjectIdentifier)
        BigInt.serializer().descriptor           -> output.writeInteger(value as BigInt)
        else -> serializer.serialize(this, value)
    }

    final override fun <T> encodeSerializableElement(
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
            encodeSerializableValue(serializer, value)
        }
    }

    final override fun <T : Any> encodeNullableSerializableElement(
        descriptor: SerialDescriptor,
        index: Int,
        serializer: SerializationStrategy<T>,
        value: T?,
    ): Unit = encodeNullableSerializableValue(serializer, value)

    final override fun <T : Any> encodeNullableSerializableValue(serializer: SerializationStrategy<T>, value: T?) {
        super.encodeNullableSerializableValue(serializer, value)
    }

    // structures: SEQUENCE and SEQUENCE OF
    // TODO: support lists
    final override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder = when (descriptor.kind) {
        StructureKind.CLASS,
        PolymorphicKind.OPEN,
        PolymorphicKind.SEALED,
             -> DerSequenceEncoder(der, output)
        else -> throw SerializationException("This serial kind is not supported as structure: $descriptor")
    }

    final override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int): CompositeEncoder = beginStructure(descriptor)

    override fun endStructure(descriptor: SerialDescriptor) {
        error("should not be called, need to override")
    }

    // this could be supported, but later
    final override fun encodeInline(descriptor: SerialDescriptor): Encoder = error("Inline encoding is not supported")
    final override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = error("Enum encoding is not supported")

    // Strings could be supported, but later
    final override fun encodeString(value: String): Unit = error("String encoding is not supported")

    // TBD what to do here
    final override fun encodeChar(value: Char): Unit = error("Char encoding is not supported")
    final override fun encodeBoolean(value: Boolean): Unit = error("Boolean encoding is not supported")
    final override fun encodeFloat(value: Float): Unit = error("Float encoding is not supported")
    final override fun encodeDouble(value: Double): Unit = error("Double encoding is not supported")

    final override fun encodeValue(value: Any): Unit = error("should not be called")
}

private class DerSequenceEncoder(
    der: DER,
    private val parentOutput: DerOutput,
    private val byteArrayOutput: ByteArrayOutput = ByteArrayOutput(),
) : DerEncoder(der, byteArrayOutput) {
    override fun endStructure(descriptor: SerialDescriptor) {
        parentOutput.writeSequence(byteArrayOutput)
    }
}
