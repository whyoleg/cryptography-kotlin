/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

import dev.whyoleg.cryptography.test.utils.*
import kotlin.reflect.*

abstract class TesterStorageApi(
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
        block: (parameters: T, parametersId: TestParametersId) -> Unit,
    ) {
        getParameters<T>(typeOf<T>()).forEach { (id, parameters, metadata) ->
            logger.log { "$storageName.getParameters: $id -> $parameters | $metadata" }
            block(parameters, TestParametersId(id))
        }
    }

    suspend inline fun <reified T : TestData> saveData(
        parametersId: TestParametersId,
        data: T,
    ): TestReference {
        val id = saveData(parametersId, data, typeOf<T>())
        val reference = TestReference(parametersId, TestDataId(id))
        logger.log { "$storageName.saveData: $reference -> $data" }
        return reference
    }

    suspend inline fun <reified T : TestData> getData(
        parametersId: TestParametersId,
        crossinline block: suspend (data: T, reference: TestReference) -> Unit,
    ) {
        getData<T>(parametersId, typeOf<T>()).forEach { (id, data, metadata) ->
            val reference = TestReference(parametersId, TestDataId(id))
            logger.log { "$storageName.getData: $reference -> $data | $metadata" }
            block(data, reference)
        }
    }

    abstract suspend fun <T : TestParameters> saveParameters(parameters: T, type: KType): String
    abstract suspend fun <T : TestParameters> getParameters(type: KType): List<Triple<String, T, Map<String, String>>>

    abstract suspend fun <T : TestData> saveData(
        parametersId: TestParametersId,
        data: T,
        type: KType,
    ): String

    abstract suspend fun <T : TestData> getData(
        parametersId: TestParametersId,
        type: KType,
    ): List<Triple<String, T, Map<String, String>>>
}
