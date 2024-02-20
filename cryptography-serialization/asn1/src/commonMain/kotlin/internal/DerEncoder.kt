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
internal class DerEncoder(
    private val der: DER,
    byteArrayOutput: ByteArrayOutput,
    private val parentOutput: DerOutput? = null,
) : AbstractEncoder() {
    private val output = DerOutput(byteArrayOutput)

    override val serializersModule: SerializersModule get() = der.serializersModule

    override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean = false

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean = true
    override fun encodeNotNullMark() {}
    override fun encodeNull(): Unit = output.writeNull()
    override fun encodeByte(value: Byte): Unit = output.writeInteger(value.toBigInt())
    override fun encodeShort(value: Short): Unit = output.writeInteger(value.toBigInt())
    override fun encodeInt(value: Int): Unit = output.writeInteger(value.toBigInt())
    override fun encodeLong(value: Long): Unit = output.writeInteger(value.toBigInt())

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T): Unit = when (serializer.descriptor) {
        ByteArraySerializer().descriptor         -> output.writeOctetString(value as ByteArray)
        BitArray.serializer().descriptor         -> output.writeBitString(value as BitArray)
        ObjectIdentifier.serializer().descriptor -> output.writeObjectIdentifier(value as ObjectIdentifier)
        BigInt.serializer().descriptor           -> output.writeInteger(value as BigInt)
        else                                     -> serializer.serialize(this, value)
    }

    // structures: SEQUENCE and SEQUENCE OF
    override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder = when (descriptor.kind) {
        StructureKind.CLASS, is PolymorphicKind -> DerEncoder(der, ByteArrayOutput(), output)
        else                                    -> throw SerializationException("This serial kind is not supported as structure: $descriptor")
    }

    override fun endStructure(descriptor: SerialDescriptor) {
        checkNotNull(parentOutput) { "Should be called after beginStructure" }.writeSequence(output)
    }

    // could be supported, but later when it will be needed
    override fun encodeInline(descriptor: SerialDescriptor): Encoder = error("Inline encoding is not supported")
    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = error("Enum encoding is not supported")
    override fun encodeString(value: String): Unit = error("String encoding is not supported")
    override fun encodeChar(value: Char): Unit = error("Char encoding is not supported")
    override fun encodeBoolean(value: Boolean): Unit = error("Boolean encoding is not supported")
    override fun encodeFloat(value: Float): Unit = error("Float encoding is not supported")
    override fun encodeDouble(value: Double): Unit = error("Double encoding is not supported")
    override fun encodeValue(value: Any): Unit = error("should not be called")
}
