package dev.whyoleg.cryptography.test.vectors.suite.api

import kotlin.reflect.*

class InMemoryApi : TestVectorApi() {
    override val keys: TestVectorStorageApi = InMemoryStorageApi()
    override val keyPairs: TestVectorStorageApi = InMemoryStorageApi()
    override val digests: TestVectorStorageApi = InMemoryStorageApi()
    override val signatures: TestVectorStorageApi = InMemoryStorageApi()
    override val ciphers: TestVectorStorageApi = InMemoryStorageApi()
}

private class InMemoryStorageApi : TestVectorStorageApi() {
    private val parametersMap = mutableMapOf<String, Any>()
    private var parametersId = 0
    private val dataMap = mutableMapOf<String, MutableMap<String, Any>>()
    private var dataId = 0
    override suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String {
        val id = (++parametersId).toString()
        parametersMap[id] = parameters
        return id
    }

    override suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Pair<String, T>> {
        return parametersMap.map {
            it.key to it.value as T
        }
    }

    override suspend fun <T : TestVectorData> saveData(parametersId: TestVectorParametersId, data: T, type: KType): String {
        val id = (++dataId).toString()
        dataMap.getOrPut(parametersId.value) { mutableMapOf() }[id] = data
        return id
    }

    override suspend fun <T : TestVectorData> getData(parametersId: TestVectorParametersId, type: KType): List<Pair<String, T>> {
        return dataMap.getValue(parametersId.value).map {
            it.key to it.value as T
        }
    }
}
