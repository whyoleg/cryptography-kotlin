/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.tests.compatibility.*
import dev.whyoleg.cryptography.providers.tests.support.*
import kotlin.test.*

abstract class CompatibilityTest<A : CryptographyAlgorithm>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {
    abstract suspend fun CompatibilityTestScope<A>.generate()
    abstract suspend fun CompatibilityTestScope<A>.validate()

    @Test
    fun generateStep() = runTest {
        disableConsoleLogging()
        runCompatibilityTestStep(
            tag = "GENERATE",
            api = { ServerApi(algorithmId.name, context, logger) },
            block = { generate() }
        )
    }

    @Test
    fun validateStep() = runTest {
        disableConsoleLogging()
        runCompatibilityTestStep(
            tag = "VALIDATE",
            api = { ServerApi(algorithmId.name, context, logger) },
            block = { validate() }
        )
    }

    @Test
    fun inMemoryTest() = runTest {
        runCompatibilityTestStep(
            tag = "GENERATE",
            api = { InMemoryApi(algorithmId.name, context, logger) },
            block = { generate() }
        )
        runCompatibilityTestStep(
            tag = "VALIDATE",
            api = { InMemoryApi(algorithmId.name, context, logger) },
            block = { validate() }
        )
    }

    private suspend fun TestScope.runCompatibilityTestStep(
        tag: String,
        api: AlgorithmTestScope<*>.() -> CompatibilityApi,
        block: suspend CompatibilityTestScope<A>.() -> Unit,
    ) {
        TestScope(logger.child(tag)).forEachAlgorithm(algorithmId) {
            CompatibilityTestScope(logger, context, provider, algorithm, api()).block()
        }
    }
}
