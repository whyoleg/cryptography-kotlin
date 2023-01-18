package dev.whyoleg.cryptography.test.vectors.suite

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlin.test.*

abstract class TestVectorTest<A : CryptographyAlgorithm>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {
    abstract suspend fun generate(
        logging: TestLoggingContext,
        api: TestVectorApi,
        provider: CryptographyProvider,
        algorithm: A,
    )

    //ignored by default
    open suspend fun compute(
        logging: TestLoggingContext,
        api: TestVectorApi,
        provider: CryptographyProvider,
        algorithm: A,
    ) {
    }

    abstract suspend fun validate(
        logging: TestLoggingContext,
        api: TestVectorApi,
        provider: CryptographyProvider,
        algorithm: A,
    )

    @Test
    fun generateTestStep() = testIt("GENERATE", ::generate)

    @Test
    fun computeTestStep() = testIt("COMPUTE", ::compute)

    @Test
    fun validateTestStep() = testIt("VALIDATE", ::validate)

    @Test
    fun localTest() = testIt { logging, api, provider, algorithm ->
        generate(logging, api, provider, algorithm)
        compute(logging, api, provider, algorithm)
        validate(logging, api, provider, algorithm)
    }

    private fun testIt(
        name: String? = null,
        testFunction: suspend (TestLoggingContext, TestVectorApi, CryptographyProvider, A) -> Unit,
    ) = runTestForEachProvider { provider ->
        val api = when (name) {
            null -> InMemoryApi(this)
            else -> ServerBasedApi(algorithmId.name, mapOf("platform" to currentPlatform, "provider" to provider.name), this)
        }
        testFunction(this, api, provider, provider.get(algorithmId))
    }
}
