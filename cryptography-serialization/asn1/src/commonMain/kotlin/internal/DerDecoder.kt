/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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
    private val der: Der,
    byteArrayInput: ByteArrayInput,
) : AbstractDecoder() {
    private val input = DerInput(byteArrayInput)

    override val serializersModule: SerializersModule get() = der.serializersModule

    private var currentIndex = 0
    private var tagOverride: ContextSpecificTag? = null
    private fun getAndResetTagOverride(): ContextSpecificTag? {
        val tag = tagOverride
        tagOverride = null
        return tag
    }

    // decodeSequentially -> always true?

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        if (input.eof) return CompositeDecoder.DECODE_DONE

        val tag = input.peakTag()

        while (true) {
            val index = currentIndex
            tagOverride = descriptor.getElementContextSpecificTag(index)

            if (descriptor.isElementOptional(index)) {
                val requiredTag = checkNotNull(tagOverride) {
                    "Optional element $descriptor[$index] must have context specific tag"
                }

                // if the tag is different,
                // then an optional element is absent,
                // and so we need to increment the index
                if (tag != requiredTag.tag) {
                    currentIndex++
                    continue
                }
            }

            return currentIndex++
        }
    }

    override fun decodeNotNullMark(): Boolean = input.isNotNull()
    override fun decodeNull(): Nothing? = input.readNull()
    override fun decodeByte(): Byte = input.readInteger(getAndResetTagOverride()).toByte()
    override fun decodeShort(): Short = input.readInteger(getAndResetTagOverride()).toShort()
    override fun decodeInt(): Int = input.readInteger(getAndResetTagOverride()).toInt()
    override fun decodeLong(): Long = input.readInteger(getAndResetTagOverride()).toLong()

    @Suppress("UNCHECKED_CAST")
    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T = when (deserializer.descriptor) {
        ByteArraySerializer().descriptor         -> input.readOctetString(getAndResetTagOverride()) as T
        BitArray.serializer().descriptor         -> input.readBitString(getAndResetTagOverride()) as T
        ObjectIdentifier.serializer().descriptor -> input.readObjectIdentifier(getAndResetTagOverride()) as T
        BigInt.serializer().descriptor           -> input.readInteger(getAndResetTagOverride()) as T
        else                                     -> deserializer.deserialize(this)
    }

    // structures: SEQUENCE and SEQUENCE OF
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder = when (descriptor.kind) {
        StructureKind.CLASS, is PolymorphicKind -> DerDecoder(der, input.readSequence(getAndResetTagOverride()))
        else                                    -> throw SerializationException("This serial kind is not supported as structure: $descriptor")
    }

    override fun decodeInline(descriptor: SerialDescriptor): Decoder = this
    override fun decodeInlineElement(descriptor: SerialDescriptor, index: Int): Decoder = this

    // could be supported, but later when it will be needed
    override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = error("Enum decoding is not supported")
    override fun decodeString(): String = error("String decoding is not supported")
    override fun decodeChar(): Char = error("Char decoding is not supported")
    override fun decodeBoolean(): Boolean = error("Boolean decoding is not supported")
    override fun decodeDouble(): Double = error("Double decoding is not supported")
    override fun decodeFloat(): Float = error("Float decoding is not supported")
    override fun decodeValue(): Any = error("should not be called")
}
