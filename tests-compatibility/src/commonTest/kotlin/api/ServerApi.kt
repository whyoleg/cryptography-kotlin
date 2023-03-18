/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.*
import dev.whyoleg.cryptography.testtool.client.*
import io.ktor.util.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*
import kotlin.reflect.*

class ServerApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
    private val logger: TestLogger,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = ServerStorageApi(algorithm, metadata, storageName, logger)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("key-pairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
}

private object Base64ByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeBase64Bytes()
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeBase64())
    }
}

private val json = Json {
    encodeDefaults = true
    prettyPrint = true
    useAlternativeNames = false
    serializersModule = SerializersModule {
        contextual(Base64ByteArraySerializer)
    }
}

@Serializable
private class Payload<T>(
    val metadata: Map<String, String>,
    val content: T,
)

private class ServerStorageApi(
    private val algorithm: String,
    private val metadata: Map<String, String>,
    storageName: String,
    logger: TestLogger,
) : CompatibilityStorageApi(storageName, logger) {
    private val cache = mutableMapOf<KType, KSerializer<Any?>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> serializer(type: KType): KSerializer<T> =
        cache.getOrPut(type) { json.serializersModule.serializer(type) } as KSerializer<T>

    private fun <T> encode(value: T, type: KType): ByteArray =
        json.encodeToString(
            Payload.serializer(serializer(type)),
            Payload(metadata, value)
        ).encodeToByteArray()

    private fun <T> decode(id: String, bytes: ByteArray, type: KType): Triple<String, T, Map<String, String>> {
        val payload = json.decodeFromString(
            Payload.serializer<T>(serializer(type)),
            bytes.decodeToString()
        )
        return Triple(id, payload.content, payload.metadata)
    }

    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        return TesttoolClient.Compatibility.saveParameters(algorithm, storageName, encode(parameters, type))
    }

    override suspend fun <T : TestParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>> {
        return TesttoolClient.Compatibility.getParameters(algorithm, storageName).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }

    override suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String {
        return TesttoolClient.Compatibility.saveData(algorithm, storageName, parametersId.value, encode(data, type))
    }

    override suspend fun <T : TestData> getData(
        parametersId: TestParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>> {
        return TesttoolClient.Compatibility.getData(algorithm, storageName, parametersId.value).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }
}
