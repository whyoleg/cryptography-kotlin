/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api.compatibility

import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.testtool.client.*
import kotlinx.coroutines.flow.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.reflect.*

class ServerApi(
    private val algorithm: String,
    private val context: TestContext,
    private val logger: TestLogger,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = ServerStorageApi(algorithm, context, storageName, logger)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("keyPairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
    override val sharedSecrets: CompatibilityStorageApi = api("sharedSecrets")
}

private val json = Json {
    prettyPrint = true
    classDiscriminator = "_"
    useAlternativeNames = false
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
    private val cachedSerializers = mutableMapOf<KType, KSerializer<Payload<Any?>>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> cachedSerializer(type: KType): KSerializer<Payload<T>> =
        cachedSerializers.getOrPut(type) { Payload.serializer(json.serializersModule.serializer(type)) } as KSerializer<Payload<T>>

    private fun <T> encode(value: T, type: KType): ByteArray =
        json.encodeToString(cachedSerializer(type), Payload(context, value)).encodeToByteArray()

    private fun <T> decode(id: String, bytes: ByteArray, type: KType): TestContent<T> {
        val payload = json.decodeFromString(cachedSerializer<T>(type), bytes.decodeToString())
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
