/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.test.*
import kotlin.test.*

abstract class CompatibilityTest<A : CryptographyAlgorithm>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {
    abstract suspend fun CompatibilityTestContext<A>.generate()
    abstract suspend fun CompatibilityTestContext<A>.validate()

    @Test
    fun generateStep() = runCompatibilityTest("GENERATE") { generate() }

    @Test
    fun validateStep() = runCompatibilityTest("VALIDATE") { validate() }

    @Test
    fun inMemoryTest() = runCompatibilityTest {
        generate()
        validate()
    }

    private fun runCompatibilityTest(
        name: String? = null,
        block: suspend CompatibilityTestContext<A>.() -> Unit,
    ) = runTestForEachAlgorithm(algorithmId) {
        val api = when (name) {
            null -> InMemoryApi(logger)
            else -> ServerApi(algorithmId.name, mapOf("platform" to currentPlatform, "provider" to provider.name), logger)
        }
        CompatibilityTestContext(logger, provider, algorithm, api).block()
    }
}
