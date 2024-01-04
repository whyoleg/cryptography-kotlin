/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api.compatibility

import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.testtool.client.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*
import kotlin.io.encoding.*
import kotlin.reflect.*

class ServerApi(
    private val algorithm: String,
    private val context: TestContext,
    private val logger: TestLogger,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = ServerStorageApi(algorithm, context, storageName, logger)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("key-pairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
}

private object Base64ByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteArray {
        return Base64.decode(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(Base64.encode(value))
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
    val context: TestContext,
    val content: T,
)

private class ServerStorageApi(
    private val algorithm: String,
    private val context: TestContext,
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
            Payload(context, value)
        ).encodeToByteArray()

    private fun <T> decode(id: String, bytes: ByteArray, type: KType): TestContent<T> {
        val payload = json.decodeFromString(
            Payload.serializer<T>(serializer(type)),
            bytes.decodeToString()
        )
        return TestContent(id, payload.content, payload.context)
    }

    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        return TesttoolClient.Compatibility.saveParameters(algorithm, storageName, encode(parameters, type))
    }

    override suspend fun <T : TestParameters> getParameters(type: KType): List<TestContent<T>> {
        return TesttoolClient.Compatibility.getParameters(algorithm, storageName).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }

    override suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String {
        return TesttoolClient.Compatibility.saveData(algorithm, storageName, parametersId.value, encode(data, type))
    }

    override suspend fun <T : TestData> getData(parametersId: TestParametersId, type: KType): List<TestContent<T>> {
        return TesttoolClient.Compatibility.getData(algorithm, storageName, parametersId.value).map { (id, bytes) ->
            decode<T>(id, bytes, type)
        }.toList()
    }
}
