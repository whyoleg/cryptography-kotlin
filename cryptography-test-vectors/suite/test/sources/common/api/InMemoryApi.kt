package dev.whyoleg.cryptography.test.vectors.suite.api

import dev.whyoleg.cryptography.test.support.*
import kotlin.reflect.*

class InMemoryApi(private val testLoggingContext: TestLoggingContext) : TestVectorApi() {
    private fun api(storageName: String): TestVectorStorageApi = InMemoryStorageApi(storageName, testLoggingContext)
    override val keys: TestVectorStorageApi = api("keys")
    override val keyPairs: TestVectorStorageApi = api("key-pairs")
    override val digests: TestVectorStorageApi = api("digests")
    override val signatures: TestVectorStorageApi = api("signatures")
    override val ciphers: TestVectorStorageApi = api("ciphers")
}

@Suppress("UNCHECKED_CAST")
private class InMemoryStorageApi(
    storageName: String,
    testLoggingContext: TestLoggingContext,
) : TestVectorStorageApi(storageName, testLoggingContext) {
    private val parametersMap: MutableMap<String, Any> = mutableMapOf()
    private var parametersId = 0
    private val dataMap: MutableMap<String, MutableMap<String, Any>> = mutableMapOf()
    private var dataId = 0
    override suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String {
        val id = (++parametersId).toString()
        parametersMap[id] = parameters
        return id
    }

    override suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>> {
        return parametersMap.map {
            Triple(it.key, it.value as T, emptyMap())
        }
    }

    override suspend fun <T : TestVectorData> saveData(
        parametersId: TestVectorParametersId,
        data: T,
        type: KType,
    ): String {
        val id = (++dataId).toString()
        dataMap.getOrPut(parametersId.value) { mutableMapOf() }[id] = data
        return id
    }

    override suspend fun <T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>> {
        return dataMap.getValue(parametersId.value).map {
            Triple(it.key, it.value as T, emptyMap())
        }
    }
}
