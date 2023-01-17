package dev.whyoleg.cryptography.test.vectors.suite

import kotlinx.coroutines.flow.*
import kotlin.reflect.*

sealed class TestVectorStorageApi {
    suspend inline fun <reified T : TestVectorParameters> saveParameters(
        parameters: T,
    ): TestVectorParametersId = TestVectorParametersId(saveParameters(parameters, typeOf<T>()))

    suspend inline fun <reified T : TestVectorParameters> getParameters(
        crossinline block: suspend (parameters: T, parametersId: TestVectorParametersId) -> Unit,
    ) {
//        getParameters<T>(typeOf<T>()).collect { block(it) }
    }

    suspend inline fun <reified T : TestVectorData> saveData(
        parametersId: TestVectorParametersId,
        data: T,
    ): TestVectorReference = TestVectorReference(parametersId, TestVectorDataId(saveData(parametersId, data, typeOf<T>())))

    suspend inline fun <reified T : TestVectorData> getData(
        parametersId: TestVectorParametersId,
        crossinline block: suspend (data: T, reference: TestVectorReference) -> Unit, //TODO: id?
    ) {

    }

    abstract suspend fun <T : TestVectorParameters> saveParameters(parameters: T, type: KType): String
    abstract fun <T : TestVectorParameters> getParameters(type: KType): Flow<T>

    abstract suspend fun <T : TestVectorData> saveData(parametersId: TestVectorParametersId, data: T, type: KType): String
    abstract suspend fun <T : TestVectorData> getData(parametersId: TestVectorParametersId, type: KType): Flow<T>
}
