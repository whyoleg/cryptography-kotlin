/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.CompatibilityStorageApi.*
import kotlin.reflect.*

class InMemory {
    private val storages = mutableMapOf<String, InMemoryStorage>()
    fun storage(name: String): InMemoryStorage = storages.getOrPut(name, ::InMemoryStorage)
}

class InMemoryApi(
    private val memory: InMemory,
    private val context: TestContext,
    private val logger: TestLogger,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi =
        InMemoryStorageApi(memory.storage(storageName), context, storageName, logger)

    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("keyPairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
    override val sharedSecrets: CompatibilityStorageApi = api("sharedSecrets")
    override val derivedSecrets: CompatibilityStorageApi = api("derivedSecrets")
}

class InMemoryStorage {
    private val parametersMap: MutableMap<String, TestContent<*>> = mutableMapOf()
    private var parametersId = 0
    private val dataMap: MutableMap<String, MutableMap<String, TestContent<*>>> = mutableMapOf()
    private var dataId = 0

    fun saveParameters(parameters: TestParameters, context: TestContext): String {
        val id = (++parametersId).toString()
        parametersMap[id] = TestContent(id, parameters, context)
        return id
    }

    fun getParameters(): List<TestContent<*>> = parametersMap.values.toList()

    fun saveData(parametersId: TestParametersId, data: TestData, context: TestContext): String {
        val id = (++dataId).toString()
        dataMap.getOrPut(parametersId.value, ::mutableMapOf)[id] = TestContent(id, data, context)
        return id
    }

    fun getData(parametersId: TestParametersId): List<TestContent<*>> = dataMap.getValue(parametersId.value).values.toList()
}

@Suppress("UNCHECKED_CAST")
private class InMemoryStorageApi(
    private val storage: InMemoryStorage,
    private val context: TestContext,
    storageName: String,
    logger: TestLogger,
) : CompatibilityStorageApi(storageName, logger) {
    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        return storage.saveParameters(parameters, context)
    }

    override suspend fun <T : TestParameters> getParameters(type: KType): List<TestContent<T>> {
        return storage.getParameters() as List<TestContent<T>>
    }

    override suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String {
        return storage.saveData(parametersId, data, context)
    }

    override suspend fun <T : TestData> getData(parametersId: TestParametersId, type: KType): List<TestContent<T>> {
        return storage.getData(parametersId) as List<TestContent<T>>
    }
}
