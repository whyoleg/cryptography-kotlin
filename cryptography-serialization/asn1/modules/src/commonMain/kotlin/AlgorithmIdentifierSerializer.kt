/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@ExperimentalSerializationApi
public abstract class AlgorithmIdentifierSerializer<AI : AlgorithmIdentifier> : KSerializer<AI> {
    protected abstract fun CompositeEncoder.encodeParameters(value: AI)
    protected abstract fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): AI

    protected fun <P : Any> CompositeEncoder.encodeParameters(serializer: KSerializer<P>, value: P?) {
        encodeNullableSerializableElement(descriptor, 1, serializer, value)
    }

    protected fun <P : Any> CompositeDecoder.decodeParameters(serializer: KSerializer<P>): P? {
        return decodeNullableSerializableElement(descriptor, 1, serializer)
    }

    @OptIn(InternalSerializationApi::class)
    final override val descriptor: SerialDescriptor = buildSerialDescriptor("AlgorithmIdentifier", PolymorphicKind.OPEN) {
        element("algorithm", ObjectIdentifier.serializer().descriptor)
        element("parameters", buildSerialDescriptor("Any", SerialKind.CONTEXTUAL))
    }

    final override fun serialize(encoder: Encoder, value: AI): Unit = encoder.encodeStructure(descriptor) {
        encodeSerializableElement(
            descriptor = descriptor,
            index = 0,
            serializer = ObjectIdentifier.serializer(),
            value = value.algorithm
        )
        encodeParameters(value)
    }

    final override fun deserialize(decoder: Decoder): AI = decoder.decodeStructure(descriptor) {
        check(decodeElementIndex(descriptor) == 0)
        val algorithm = decodeSerializableElement(
            descriptor = descriptor,
            index = 0,
            deserializer = ObjectIdentifier.serializer()
        )
        when (val idx = decodeElementIndex(descriptor)) {
            1 -> {
                val parameters = decodeParameters(algorithm)
                check(decodeElementIndex(descriptor) == CompositeDecoder.DECODE_DONE)
                parameters
            }
            CompositeDecoder.DECODE_DONE -> {
                // Some algorithms (e.g., Ed25519/Ed448/X25519/X448 per RFC 8410) omit parameters.
                // Delegate to subclass to construct an identifier without consuming parameters from the stream.
                decodeParameters(algorithm)
            }
            else -> error("Unexpected element index: $idx")
        }
    }
}
