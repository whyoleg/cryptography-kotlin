package dev.whyoleg.cryptography.test.vectors.suite.api

import dev.whyoleg.cryptography.test.support.*
import kotlin.reflect.*

sealed class TestVectorStorageApi(
    val storageName: String,
    val testLoggingContext: TestLoggingContext,
) {
    suspend inline fun <reified T : TestVectorParameters> saveParameters(
        parameters: T,
    ): TestVectorParametersId {
        val id = saveParameters(parameters, typeOf<T>())
        testLoggingContext.log("$storageName.saveParameters: $id -> $parameters")
        return TestVectorParametersId(id)
    }

    suspend inline fun <reified T : TestVectorParameters> getParameters(
        block: (parameters: T, parametersId: TestVectorParametersId) -> Unit,
    ) {
        getParameters<T>(typeOf<T>()).forEach { (id, parameters, metadata) ->
            testLoggingContext.log("$storageName.getParameters: $id -> $parameters | $metadata")
            block(parameters, TestVectorParametersId(id))
        }
    }

    suspend inline fun <reified T : TestVectorData> saveData(
        parametersId: TestVectorParametersId,
        data: T,
    ): TestVectorReference {
        val id = saveData(parametersId, data, typeOf<T>())
        val reference = TestVectorReference(parametersId, TestVectorDataId(id))
        testLoggingContext.log("$storageName.saveData: $reference -> $data")
        return reference
    }

    suspend inline fun <reified T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        crossinline block: suspend (data: T, reference: TestVectorReference) -> Unit,
    ) {
        getData<T>(parametersId, typeOf<T>()).forEach { (id, data, metadata) ->
            val reference = TestVectorReference(parametersId, TestVectorDataId(id))
            testLoggingContext.log("$storageName.getData: $reference -> $data | $metadata")
            block(data, reference)
        }
    }

    abstract suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String
    abstract suspend fun <T : TestVectorParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>>

    abstract suspend fun <T : TestVectorData> saveData(
        parametersId: TestVectorParametersId,
        data: T,
        type: KType,
    ): String

    abstract suspend fun <T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>>
}
