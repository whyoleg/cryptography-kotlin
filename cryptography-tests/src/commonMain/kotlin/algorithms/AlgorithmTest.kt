/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.tests.*
import kotlinx.coroutines.test.*
import kotlin.test.*

// getting the algorithm from the provider, the root operation of every test, see `AlgorithmTest.algorithmLimitation`
data class GetAlgorithmTestOperation(val algorithmId: CryptographyAlgorithmId<*>) : TestOperation {
    override fun toString(): String = "GetAlgorithm(${algorithmId.name})"
}

// Test suite of a single algorithm, `[run-id]/[suite-id]/...`: the root validator and test data generation
abstract class AlgorithmTest<A : CryptographyAlgorithm, V : TestInputValidator>(
    private val provider: CryptographyProvider,
    private val algorithmId: CryptographyAlgorithmId<A>,
    // limitation of the algorithm as a whole:
    // * `fails` - the provider doesn't support the algorithm, so it must not return it
    // * `skip` - the algorithm is supported, but can't be tested
    private val algorithmLimitation: (TestLimitationScope.() -> TestLimitation?)? = null,
    // f.e. when an algorithm supports different operations, which are tested separately
    private val suiteId: String = algorithmId.name,
) {
    // root validator of the algorithm, limitations of operations are declared by validators, see `TestValidatorScope`;
    // validators must be self-sufficient, as during restoration only stored data is available
    protected abstract fun TestValidatorScope.validator(algorithm: A): V

    // generates, validates and stores test data
    protected fun test(
        id: String,
        store: Boolean = true,
        block: suspend context(TestGenerationContext) V.(algorithm: A) -> Unit,
    ): TestResult = runGenerationTest(provider, suiteId, id, store) {
        val algorithm = getAlgorithm()
        TestValidatorScope.validator(algorithm).block(algorithm)
    }

    // the provider returns the algorithm only if it's not limited with `fails`
    @Test
    fun algorithmSupport(): TestResult = runTest {
        val limitation = algorithmLimitation?.invoke(TestLimitationScope(TestEnvironment(provider)))
        assertEquals(
            expected = limitation?.kind != TestLimitation.Kind.Fails,
            actual = provider.getOrNull(algorithmId) != null,
            message = "${algorithmId.name} support by ${provider.name}" + limitation?.let { " (${it.kind}: ${it.description})" }.orEmpty(),
        )
    }

    // validates all data stored by other runs (other providers, platforms, or previous runs of the same provider)
    @Test
    fun restore(): TestResult = runRestorationTest(provider, suiteId) {
        TestValidatorScope.validator(getAlgorithm()).restore()
    }

    context(context: TestValidationContext)
    private suspend fun getAlgorithm(): A = operation(
        operation = GetAlgorithmTestOperation(algorithmId),
        limitation = algorithmLimitation?.let { limitation -> { limitation() } },
    ) { provider.get(algorithmId) }
}
