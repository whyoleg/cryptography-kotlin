/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.providers.tests.support.*
import kotlin.reflect.*

class InMemoryApi(
    private val algorithm: String,
    private val context: TestContext,
    private val logger: TestLogger,
) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = InMemoryStorageApi(algorithm, context, storageName, logger)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("key-pairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
}

@Suppress("UNCHECKED_CAST")
private class InMemoryStorageApi(
    algorithm: String,
    private val context: TestContext,
    storageName: String,
    logger: TestLogger,
) : CompatibilityStorageApi(storageName, logger) {
    private val name = "$algorithm/$storageName"
    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        return saveParameters(name, parameters, context)
    }

    override suspend fun <T : TestParameters> getParameters(type: KType): List<TestContent<T>> {
        return getParameters(name) as List<TestContent<T>>
    }

    override suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String {
        return saveData(name, parametersId, data, context)
    }

    override suspend fun <T : TestData> getData(parametersId: TestParametersId, type: KType): List<TestContent<T>> {
        return getData(name, parametersId) as List<TestContent<T>>
    }

    private companion object {
        private class Storage {
            val parametersMap: MutableMap<String, TestContent<*>> = mutableMapOf()
            var parametersId = 0
            val dataMap: MutableMap<String, MutableMap<String, TestContent<*>>> = mutableMapOf()
            var dataId = 0
        }

        private val storages = mutableMapOf<String, Storage>()

        fun saveParameters(storageName: String, parameters: TestParameters, context: TestContext): String =
            with(storages.getOrPut(storageName, ::Storage)) {
                val id = (++parametersId).toString()
                parametersMap[id] = TestContent(id, parameters, context)
                id
            }

        fun getParameters(storageName: String): List<TestContent<*>> =
            with(storages.getValue(storageName)) {
                parametersMap.values.toList()
            }

        fun saveData(storageName: String, parametersId: TestParametersId, data: TestData, context: TestContext): String =
            with(storages.getOrPut(storageName, ::Storage)) {
                val id = (++dataId).toString()
                dataMap.getOrPut(parametersId.value, ::mutableMapOf)[id] = TestContent(id, data, context)
                id
            }

        fun getData(storageName: String, parametersId: TestParametersId): List<TestContent<*>> =
            with(storages.getValue(storageName)) {
                dataMap.getValue(parametersId.value).values.toList()
            }
    }
}
