/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

@ExperimentalSerializationApi
public abstract class AlgorithmIdentifierSerializer : KSerializer<AlgorithmIdentifier> {
    protected abstract fun CompositeEncoder.encodeParameters(value: AlgorithmIdentifier)
    protected abstract fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): AlgorithmIdentifier

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

    final override fun serialize(encoder: Encoder, value: AlgorithmIdentifier): Unit = encoder.encodeStructure(descriptor) {
        encodeSerializableElement(
            descriptor = descriptor,
            index = 0,
            serializer = ObjectIdentifier.serializer(),
            value = value.algorithm
        )
        encodeParameters(value)
    }

    final override fun deserialize(decoder: Decoder): AlgorithmIdentifier = decoder.decodeStructure(descriptor) {
        check(decodeElementIndex(descriptor) == 0)
        val algorithm = decodeSerializableElement(
            descriptor = descriptor,
            index = 0,
            deserializer = ObjectIdentifier.serializer()
        )
        check(decodeElementIndex(descriptor) == 1)
        val parameters = decodeParameters(algorithm)
        check(decodeElementIndex(descriptor) == CompositeDecoder.DECODE_DONE)
        parameters
    }
}

@OptIn(ExperimentalSerializationApi::class)
internal object DefaultAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer() {
    override fun CompositeEncoder.encodeParameters(value: AlgorithmIdentifier): Unit = when (value) {
        is RsaAlgorithmIdentifier     -> encodeParameters(NothingSerializer(), RsaAlgorithmIdentifier.parameters)
        is EcAlgorithmIdentifier      -> encodeParameters(EcParameters.serializer(), value.parameters)
        is UnknownAlgorithmIdentifier -> encodeParameters(NothingSerializer(), value.parameters)
        else                          -> encodeParameters(NothingSerializer(), null)
    }

    override fun CompositeDecoder.decodeParameters(algorithm: ObjectIdentifier): AlgorithmIdentifier = when (algorithm) {
        ObjectIdentifier.RSA -> {
            // null parameters
            decodeParameters(NothingSerializer())
            RsaAlgorithmIdentifier
        }
        ObjectIdentifier.EC  -> EcAlgorithmIdentifier(decodeParameters(EcParameters.serializer()))
        else                 -> {
            // TODO: somehow we should ignore parameters here
            UnknownAlgorithmIdentifier(algorithm)
        }
    }
}
