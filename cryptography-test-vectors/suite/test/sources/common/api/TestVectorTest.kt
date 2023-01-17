package dev.whyoleg.cryptography.test.vectors.suite.api

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.support.*
import kotlin.test.*

abstract class TestVectorTest(private val algorithm: String) {
    abstract suspend fun generate(api: TestVectorApi, provider: CryptographyProvider)
    open suspend fun compute(api: TestVectorApi, provider: CryptographyProvider) {} //ignored by default
    abstract suspend fun validate(api: TestVectorApi, provider: CryptographyProvider)

    @Test
    fun generateTestStep() = testIt("GENERATE", ::generate)

    @Test
    fun computeTestStep() = testIt("COMPUTE", ::compute)

    @Test
    fun validateTestStep() = testIt("VALIDATE", ::validate)

    @Test
    fun localTest() = testIt("LOCAL") { api, provider ->
        generate(api, provider)
        compute(api, provider)
        validate(api, provider)
    }

    //TODO: local must use local api
    private fun testIt(
        name: String,
        testFunction: suspend (TestVectorApi, CryptographyProvider) -> Unit,
    ) =
        runTestForEachProvider { provider ->
            println(name)
            testFunction(TestVectorApi(), provider)
        }
}
