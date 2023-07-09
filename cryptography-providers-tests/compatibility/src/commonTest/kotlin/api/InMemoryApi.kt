/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.providers.tests.support.*
import kotlin.reflect.*

class InMemoryApi(private val logger: TestLogger) : CompatibilityApi() {
    private fun api(storageName: String): CompatibilityStorageApi = InMemoryStorageApi(storageName, logger)
    override val keys: CompatibilityStorageApi = api("keys")
    override val keyPairs: CompatibilityStorageApi = api("key-pairs")
    override val digests: CompatibilityStorageApi = api("digests")
    override val signatures: CompatibilityStorageApi = api("signatures")
    override val ciphers: CompatibilityStorageApi = api("ciphers")
}

@Suppress("UNCHECKED_CAST")
private class InMemoryStorageApi(
    storageName: String,
    logger: TestLogger,
) : CompatibilityStorageApi(storageName, logger) {
    private val parametersMap: MutableMap<String, Any> = mutableMapOf()
    private var parametersId = 0
    private val dataMap: MutableMap<String, MutableMap<String, Any>> = mutableMapOf()
    private var dataId = 0
    override suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String {
        val id = (++parametersId).toString()
        parametersMap[id] = parameters
        return id
    }

    override suspend fun <T : TestParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>> {
        return parametersMap.map {
            Triple(it.key, it.value as T, emptyMap())
        }
    }

    override suspend fun <T : TestData> saveData(
        parametersId: TestParametersId,
        data: T,
        type: KType,
    ): String {
        val id = (++dataId).toString()
        dataMap.getOrPut(parametersId.value) { mutableMapOf() }[id] = data
        return id
    }

    override suspend fun <T : TestData> getData(
        parametersId: TestParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>> {
        return dataMap.getValue(parametersId.value).map {
            Triple(it.key, it.value as T, emptyMap())
        }
    }
}
