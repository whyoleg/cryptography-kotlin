/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlin.reflect.*

@ExperimentalSerializationApi
public abstract class AlgorithmIdentifierSerializer : KSerializer<AlgorithmIdentifier> {
    private val byClass = mutableMapOf<KClass<*>, AlgorithmEntry>()
    private val byOid = mutableMapOf<ObjectIdentifier, AlgorithmEntry>()

    private fun algorithm(oid: ObjectIdentifier, cls: KClass<*>, entry: AlgorithmEntry) {
        byClass[cls] = entry
        byOid[oid] = entry
    }

    @Suppress("UNCHECKED_CAST")
    protected fun <P, T : AlgorithmIdentifier> algorithm(
        oid: ObjectIdentifier,
        cls: KClass<T>,
        parametersSerializer: KSerializer<P>,
        factory: (P?) -> T,
    ): Unit = algorithm(oid, cls, AlgorithmEntry(parametersSerializer, factory as (Any?) -> AlgorithmIdentifier))

    protected fun <T : AlgorithmIdentifier> algorithm(
        oid: ObjectIdentifier,
        cls: KClass<T>,
        instance: T,
        encodeNull: Boolean,
    ): Unit = algorithm(oid, cls, if (encodeNull) NothingSerializer() else AbsentNothingSerializer) { instance }

    protected inline fun <reified T : AlgorithmIdentifier> algorithm(
        oid: ObjectIdentifier,
        instance: T,
        encodeNull: Boolean,
    ): Unit = algorithm(oid, T::class, instance, encodeNull)

    protected inline fun <reified P, reified T : AlgorithmIdentifier> algorithm(
        oid: ObjectIdentifier,
        noinline factory: (P?) -> T,
    ): Unit = algorithm(oid, T::class, serializer<P>(), factory)

    // impl details

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

        @Suppress("UNCHECKED_CAST")
        encodeNullableSerializableElement(
            descriptor = descriptor,
            index = 1,
            serializer = byClass[value::class]?.serializer as? KSerializer<Any?> ?: error("No serializer for ${value::class}"),
            value = value.parameters
        )
    }

    final override fun deserialize(decoder: Decoder): AlgorithmIdentifier = decoder.decodeStructure(descriptor) {
        check(decodeElementIndex(descriptor) == 0)
        val algorithm = decodeSerializableElement(
            descriptor = descriptor,
            index = 0,
            deserializer = ObjectIdentifier.serializer()
        )

        val entry = byOid[algorithm] ?: error("Unknown algorithm: $algorithm")

        val parameters = when (val index = decodeElementIndex(descriptor)) {
            1                            -> {
                val parameters = decodeNullableSerializableElement(
                    descriptor = descriptor,
                    index = 1,
                    deserializer = entry.serializer
                )
                check(decodeElementIndex(descriptor) == CompositeDecoder.DECODE_DONE)
                parameters
            }
            CompositeDecoder.DECODE_DONE -> null // no parameters
            else                         -> error("Unexpected element index: $index")
        }

        entry.factory.invoke(parameters)
    }

    private class AlgorithmEntry(
        val serializer: KSerializer<out Any?>,
        val factory: (Any?) -> AlgorithmIdentifier,
    )
}

@OptIn(ExperimentalSerializationApi::class)
internal object DefaultAlgorithmIdentifierSerializer : AlgorithmIdentifierSerializer() {
    init {
        algorithm(ObjectIdentifier.RSA, RsaAlgorithmIdentifier, encodeNull = true)
        algorithm(ObjectIdentifier.EC, ::EcAlgorithmIdentifier)

        // in edvard curves algorithms, we don't need to encode parameters at all, not even `null`

        algorithm(ObjectIdentifier.X25519, X25519AlgorithmIdentifier, encodeNull = false)
        algorithm(ObjectIdentifier.X448, X448AlgorithmIdentifier, encodeNull = false)

        algorithm(ObjectIdentifier.Ed25519, Ed25519AlgorithmIdentifier, encodeNull = false)
        algorithm(ObjectIdentifier.Ed448, Ed448AlgorithmIdentifier, encodeNull = false)
    }
}

@OptIn(ExperimentalSerializationApi::class)
private object AbsentNothingSerializer : KSerializer<Nothing?> {
    override val descriptor: SerialDescriptor = NothingSerializer().descriptor.nullable

    override fun serialize(encoder: Encoder, value: Nothing?) {
        // do nothing
    }

    override fun deserialize(decoder: Decoder): Nothing? {
        return null
    }
}
