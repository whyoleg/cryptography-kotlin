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
internal class DerDecoder(
    private val der: DER,
    byteArrayInput: ByteArrayInput,
) : AbstractDecoder() {
    private val input = DerInput(byteArrayInput)

    override val serializersModule: SerializersModule get() = der.serializersModule

    private var currentIndex = 0
    override fun decodeSequentially(): Boolean = true
    override fun decodeElementIndex(descriptor: SerialDescriptor): Int = when {
        input.eof -> CompositeDecoder.DECODE_DONE
        else      -> currentIndex++
    }

    override fun decodeNotNullMark(): Boolean = input.isNotNull()
    override fun decodeNull(): Nothing? = input.readNull()
    override fun decodeByte(): Byte = input.readInteger().toByte()
    override fun decodeShort(): Short = input.readInteger().toShort()
    override fun decodeInt(): Int = input.readInteger().toInt()
    override fun decodeLong(): Long = input.readInteger().toLong()

    @Suppress("UNCHECKED_CAST")
    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T = when (deserializer.descriptor) {
        ByteArraySerializer().descriptor         -> input.readOctetString() as T
        BitArray.serializer().descriptor         -> input.readBitString() as T
        ObjectIdentifier.serializer().descriptor -> input.readObjectIdentifier() as T
        BigInt.serializer().descriptor           -> input.readInteger() as T
        else                                     -> deserializer.deserialize(this)
    }

    // structures: SEQUENCE and SEQUENCE OF
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder = when (descriptor.kind) {
        StructureKind.CLASS, is PolymorphicKind -> DerDecoder(der, input.readSequence())
        else                                    -> throw SerializationException("This serial kind is not supported as structure: $descriptor")
    }

    // could be supported, but later when it will be needed
    override fun decodeInline(descriptor: SerialDescriptor): Decoder = error("Inline decoding is not supported")
    override fun decodeInlineElement(descriptor: SerialDescriptor, index: Int): Decoder = error("Inline decoding is not supported")
    override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = error("Enum decoding is not supported")
    override fun decodeString(): String = error("String decoding is not supported")
    override fun decodeChar(): Char = error("Char decoding is not supported")
    override fun decodeBoolean(): Boolean = error("Boolean decoding is not supported")
    override fun decodeDouble(): Double = error("Double decoding is not supported")
    override fun decodeFloat(): Float = error("Float decoding is not supported")
    override fun decodeValue(): Any = error("should not be called")
}
