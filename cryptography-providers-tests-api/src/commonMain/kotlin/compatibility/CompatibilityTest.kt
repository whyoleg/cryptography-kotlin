/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.tests.api.*
import kotlin.test.*

abstract class CompatibilityTest<A : CryptographyAlgorithm>(
    protected val algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : ProviderTest(provider) {
    abstract suspend fun CompatibilityTestScope<A>.generate()
    abstract suspend fun CompatibilityTestScope<A>.validate()

    @Test
    fun generateStep() = testAlgorithm(algorithmId) {
        val logger = logger.child("GENERATE")
        runCompatibilityTestStep(logger, ServerApi(algorithmId.name, context, logger)) { generate() }
    }

    @Test
    fun validateStep() = testAlgorithm(algorithmId) {
        val logger = logger.child("VALIDATE")
        runCompatibilityTestStep(logger, ServerApi(algorithmId.name, context, logger)) { validate() }
    }

    @Test
    fun inMemoryTest() = testAlgorithm(algorithmId) {
        var logger = logger.child("GENERATE")
        runCompatibilityTestStep(logger, InMemoryApi(algorithmId.name, context, logger)) { generate() }
        logger = logger.child("VALIDATE")
        runCompatibilityTestStep(logger, InMemoryApi(algorithmId.name, context, logger)) { validate() }
    }

    private suspend fun AlgorithmTestScope<A>.runCompatibilityTestStep(
        logger: TestLogger,
        api: CompatibilityApi,
        block: suspend CompatibilityTestScope<A>.() -> Unit,
    ) {
        CompatibilityTestScope(logger, context, provider, algorithm, api).block()
    }
}
