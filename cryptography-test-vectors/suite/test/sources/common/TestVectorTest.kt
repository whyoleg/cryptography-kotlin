package dev.whyoleg.cryptography.test.vectors.suite

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.support.*
import kotlin.test.*

abstract class TestVectorTest<A : CryptographyAlgorithm>(
    private val algorithmId: CryptographyAlgorithmId<A>,
) {
    abstract suspend fun generate(api: TestVectorApi, provider: CryptographyProvider, algorithm: A)
    open suspend fun compute(api: TestVectorApi, provider: CryptographyProvider, algorithm: A) {} //ignored by default
    abstract suspend fun validate(api: TestVectorApi, provider: CryptographyProvider, algorithm: A)

    @Test
    fun generateTestStep() = testIt("GENERATE", ::generate)

    @Test
    fun computeTestStep() = testIt("COMPUTE", ::compute)

    @Test
    fun validateTestStep() = testIt("VALIDATE", ::validate)

    @Test
    fun localTest() = testIt { api, provider, algorithm ->
        generate(api, provider, algorithm)
        compute(api, provider, algorithm)
        validate(api, provider, algorithm)
    }

    //TODO: local must use local api
    private fun testIt(
        name: String? = null,
        testFunction: suspend (TestVectorApi, CryptographyProvider, A) -> Unit,
    ) = runTestForEachProvider { provider ->
        val api = when (name) {
            null -> InMemoryApi
            else -> RemoteApi(algorithmId.name, mapOf("platform" to currentPlatform, "provider" to provider.name))
        }
        testFunction(api, provider, provider.get(algorithmId))
    }
}
