/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

import dev.whyoleg.cryptography.test.utils.*
import kotlin.reflect.*

class InMemoryApi(private val logger: TestLogger) : TesterApi() {
    private fun api(storageName: String): TesterStorageApi = InMemoryStorageApi(storageName, logger)
    override val keys: TesterStorageApi = api("keys")
    override val keyPairs: TesterStorageApi = api("key-pairs")
    override val digests: TesterStorageApi = api("digests")
    override val signatures: TesterStorageApi = api("signatures")
    override val ciphers: TesterStorageApi = api("ciphers")
}

@Suppress("UNCHECKED_CAST")
private class InMemoryStorageApi(
    storageName: String,
    logger: TestLogger,
) : TesterStorageApi(storageName, logger) {
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
