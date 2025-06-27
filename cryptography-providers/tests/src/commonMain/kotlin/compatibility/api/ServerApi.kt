/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.testtool.api.*
import dev.whyoleg.cryptography.testtool.client.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*
import kotlin.reflect.*
import kotlin.uuid.*

class ServerApi(
    private val algorithm: String,
    private val context: TestContext,
    private val logger: TestLogger,
    private val client: TesttoolClient,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = ServerStorageApi(algorithm, context, storageName, logger, client)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("keyPairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
    override val sharedSecrets: CompatibilityStorageApi = api("sharedSecrets")
    override val derivedSecrets: CompatibilityStorageApi = api("derivedSecrets")
}

@Serializable
private class Payload<T>(
    val context: TestContext,
    val content: T,
)

@OptIn(ExperimentalSerializationApi::class, ExperimentalUuidApi::class)
private class ServerStorageApi(
    private val algorithm: String,
    private val context: TestContext,
    storageName: String,
    logger: TestLogger,
    private val client: TesttoolClient,
) : CompatibilityStorageApi(storageName, logger) {
    private val cachedSerializers = mutableMapOf<KType, KSerializer<Payload<Any?>>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> cachedSerializer(type: KType): KSerializer<Payload<T>> =
        cachedSerializers.getOrPut(type) { Payload.serializer(ConfiguredCbor.serializersModule.serializer(type)) } as KSerializer<Payload<T>>

    private fun <T> encode(value: T, type: KType): ByteArray =
        ConfiguredCbor.encodeToByteArray(cachedSerializer(type), Payload(context, value))//.encodeToByteArray()

    private fun <T> decode(id: String, bytes: ByteArray, type: KType): TestContent<T> {
        val payload = ConfiguredCbor.decodeFromByteArray(cachedSerializer<T>(type), bytes)
        return TestContent(id, payload.content, payload.context)
    }

    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        val id = Uuid.random().toString()
        client.save(SaveParameters(id, algorithm, storageName, encode(parameters, type)))
        return id
    }

    override fun <T : TestParameters> getParameters(type: KType): Flow<TestContent<T>> {
        return client.get(GetParameters(Uuid.random().toString(), algorithm, storageName)).map { (_, id, payload) ->
            decode(id, payload, type)
        }
    }

    override suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String {
        val id = Uuid.random().toString()
        client.save(SaveData(id, algorithm, storageName, parametersId.value, encode(data, type)))
        return id
    }

    override fun <T : TestData> getData(parametersId: TestParametersId, type: KType): Flow<TestContent<T>> {
        return client.get(GetData(Uuid.random().toString(), algorithm, storageName, parametersId.value)).map { (_, id, payload) ->
            decode(id, payload, type)
        }
    }
}
