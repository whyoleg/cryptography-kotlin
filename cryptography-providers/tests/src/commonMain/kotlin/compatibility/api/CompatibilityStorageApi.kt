/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.coroutines.flow.*
import kotlin.reflect.*

abstract class CompatibilityStorageApi(
    val storageName: String,
    val logger: TestLogger,
) {
    suspend inline fun <reified T : TestParameters> saveParameters(
        parameters: T,
    ): TestParametersId {
        val id = saveParameters(parameters, typeOf<T>())
        logger.log { "$storageName.saveParameters: $id -> $parameters" }
        return TestParametersId(id)
    }

    suspend inline fun <reified T : TestParameters> getParameters(
        crossinline block: suspend (parameters: T, parametersId: TestParametersId, context: TestContext) -> Unit,
    ) {
        getParameters<T>(typeOf<T>()).collect { (id, parameters, context) ->
            logger.log { "$storageName.getParameters: $id -> $parameters | $context" }
            block(parameters, TestParametersId(id), context)
        }
    }

    suspend inline fun <reified T : TestData> saveData(parametersId: TestParametersId, data: T): TestReference {
        val id = saveData(parametersId, data, typeOf<T>())
        val reference = TestReference(parametersId, TestDataId(id))
        logger.log { "$storageName.saveData: $reference -> $data" }
        return reference
    }

    suspend inline fun <reified T : TestData> getData(
        parametersId: TestParametersId,
        crossinline block: suspend (data: T, reference: TestReference, context: TestContext) -> Unit,
    ) {
        getData<T>(parametersId, typeOf<T>()).collect { (id, data, context) ->
            val reference = TestReference(parametersId, TestDataId(id))
            logger.log { "$storageName.getData: $reference -> $data | $context" }
            block(data, reference, context)
        }
    }

    abstract suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String
    abstract fun <T : TestParameters> getParameters(type: KType): Flow<TestContent<T>>

    abstract suspend fun <T : TestData> saveData(parametersId: TestParametersId, data: T, type: KType): String
    abstract fun <T : TestData> getData(parametersId: TestParametersId, type: KType): Flow<TestContent<T>>

    data class TestContent<T>(
        val id: String,
        val content: T,
        val context: TestContext,
    )
}
