package dev.whyoleg.cryptography.test.vectors.suite

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlin.test.*

abstract class TestVectorTest<A : CryptographyAlgorithm>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {
    abstract suspend fun TestLoggingContext.generate(api: TestVectorApi, provider: CryptographyProvider, algorithm: A)
    open suspend fun TestLoggingContext.compute(api: TestVectorApi, provider: CryptographyProvider, algorithm: A) {} //ignored by default
    abstract suspend fun TestLoggingContext.validate(api: TestVectorApi, provider: CryptographyProvider, algorithm: A)

    @Test
    fun generateTestStep() = testIt("GENERATE") { api, provider, algorithm -> generate(api, provider, algorithm) }

    @Test
    fun computeTestStep() = testIt("COMPUTE") { api, provider, algorithm -> compute(api, provider, algorithm) }

    @Test
    fun validateTestStep() = testIt("VALIDATE") { api, provider, algorithm -> validate(api, provider, algorithm) }

    @Test
    fun localTest() = testIt { api, provider, algorithm ->
        generate(api, provider, algorithm)
        compute(api, provider, algorithm)
        validate(api, provider, algorithm)
    }

    private fun testIt(
        name: String? = null,
        testFunction: suspend TestLoggingContext.(TestVectorApi, CryptographyProvider, A) -> Unit,
    ) = runTestForEachProvider { provider ->
        val api = when (name) {
            null -> InMemoryApi(this)
            else -> ServerBasedApi(algorithmId.name, mapOf("platform" to currentPlatform, "provider" to provider.name), this)
        }
        testFunction(api, provider, provider.get(algorithmId))
    }
}
