package dev.whyoleg.cryptography.test.vectors.suite

import kotlin.reflect.*

sealed class TestVectorStorageApi {
    suspend inline fun <reified T : TestVectorParameters> saveParameters(
        parameters: T,
    ): TestVectorParametersId {
        val id = saveParameters(parameters, typeOf<T>())
        println("saveParameters: $id -> $parameters")
        return TestVectorParametersId(id)
    }

    suspend inline fun <reified T : TestVectorParameters> getParameters(
        block: (parameters: T, parametersId: TestVectorParametersId) -> Unit,
    ) {
        getParameters<T>(typeOf<T>()).forEach { (id, parameters) ->
            println("getParameters: $id -> $parameters")
            block(parameters, TestVectorParametersId(id))
        }
    }

    suspend inline fun <reified T : TestVectorData> saveData(
        parametersId: TestVectorParametersId,
        data: T,
    ): TestVectorReference {
        val id = saveData(parametersId, data, typeOf<T>())
        val reference = TestVectorReference(parametersId, TestVectorDataId(id))
        println("saveData: $reference -> $data")
        return reference
    }

    suspend inline fun <reified T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        crossinline block: suspend (data: T, reference: TestVectorReference) -> Unit,
    ) {
        getData<T>(parametersId, typeOf<T>()).forEach { (id, data) ->
            val reference = TestVectorReference(parametersId, TestVectorDataId(id))
            println("getData: $reference -> $data")
            block(data, reference)
        }
    }

    abstract suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String
    abstract suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Pair<String, T>>

    abstract suspend fun <T : TestVectorData> saveData(parametersId: TestVectorParametersId, data: T, type: KType): String
    abstract suspend fun <T : TestVectorData> getData(parametersId: TestVectorParametersId, type: KType): List<Pair<String, T>>
}
