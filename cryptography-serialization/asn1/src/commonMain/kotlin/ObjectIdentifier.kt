/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.concurrent.*

@Serializable(ObjectIdentifierSerializer::class)
public class ObjectIdentifier private constructor(
    private val derBytes: ByteArray,
    @Volatile private var stringRepresentation: String?,
) {
    init {
        // TODO: validate bytes value
    }

    override fun toString(): String {
        if (stringRepresentation == null) {
            stringRepresentation = derBytesToString(derBytes)
        }
        return stringRepresentation!!
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ObjectIdentifier) return false

        return derBytes.contentEquals(other.derBytes)
    }

    override fun hashCode(): Int {
        return derBytes.contentHashCode()
    }

    // used by encoder
    internal fun toDerBytes(): ByteArray = derBytes

    public companion object {
        public fun parse(text: String): ObjectIdentifier = ObjectIdentifierCache.getOrPut(text) {
            ObjectIdentifier(derBytes = stringToDerBytes(text), stringRepresentation = text)
        }

        // used by decoder
        internal fun fromDerBytes(bytes: ByteArray): ObjectIdentifier = ObjectIdentifier(derBytes = bytes, stringRepresentation = null)

        // TODO: may be it's possible to optimize it and dont' use `ByteStringBuilder` (needs benchmarks)
        // TODO: support elements bigger than `Int`
        // TODO: recheck if `indexOf` is faster than `split('.')`
        @OptIn(UnsafeByteStringApi::class)
        private fun stringToDerBytes(text: String): ByteArray {
            fun ByteStringBuilder.appendElement(element: Int) {
                if (element < 128) return append(element.toByte())

                val l = (Int.SIZE_BITS - element.countLeadingZeroBits()) / 7
                repeat(l) {
                    // zero should not be encoded
                    val value = element ushr (l - it) * 7
                    if (value != 0) append(((value and 0b01111111) or 0b10000000).toByte())
                }
                append((element and 0b01111111).toByte())
            }

            val elements = text.split('.')
            check(elements.size >= 2) { "at least 2 components expected but was ${elements.size}" }
            UnsafeByteStringOperations.withByteArrayUnsafe(buildByteString {
                appendElement(elements[0].toInt() * 40 + elements[1].toInt())
                repeat(elements.size - 2) { appendElement(elements[it + 2].toInt()) }
            }) { return it }
        }

        // TODO: support elements bigger than `Int`
        private fun derBytesToString(bytes: ByteArray): String {
            var index = 0

            fun readElement(): Int {
                var element = 0
                do {
                    val b = bytes[index++].toInt()
                    element = (element shl 7) + (b and 0b01111111)
                } while (b and 0b10000000 == 0b10000000)
                check(element >= 0) { "element overflow: $element" }
                return element
            }

            return buildString {
                // 0.(0..<40) = 0..<40
                // 1.(0..<40) = 40..<80
                // 2.(0..XXX) = 80..XXX+80
                val first = readElement()
                when {
                    first < 40 -> append('0').append('.').append(first)
                    first < 80 -> append('1').append('.').append(first - 40)
                    else       -> append('2').append('.').append(first - 80)
                }

                while (index != bytes.size) append('.').append(readElement())
            }
        }
    }
}

internal expect val ObjectIdentifierCache: MutableMap<String, ObjectIdentifier>

internal object ObjectIdentifierSerializer : KSerializer<ObjectIdentifier> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: ObjectIdentifier) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): ObjectIdentifier {
        return ObjectIdentifier.parse(decoder.decodeString())
    }
}
