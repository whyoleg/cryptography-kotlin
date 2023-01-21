package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlin.test.*

open class CompatibilityTestContext<A : CryptographyAlgorithm>(
    logger: TestLogger,
    provider: CryptographyProvider,
    algorithm: A,
    val api: TesterApi,
) : AlgorithmTestContext<A>(logger, provider, algorithm)

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
    fun inMemoryTest() = runCompatibilityTest { generate(); validate() }

    private fun runCompatibilityTest(
        name: String? = null,
        block: suspend CompatibilityTestContext<A>.() -> Unit,
    ) = runTestForEachAlgorithm(algorithmId) {
        val api = when (name) {
            null -> InMemoryApi(logger)
            else -> ServerBasedApi(algorithmId.name, mapOf("platform" to currentPlatform, "provider" to provider.name), logger)
        }
        CompatibilityTestContext(logger, provider, algorithm, api).block()
    }
}
