package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.test.api.*
import dev.whyoleg.cryptography.test.client.*
import dev.whyoleg.cryptography.test.suite.algorithms.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlinx.serialization.*
import kotlin.test.*

class GenerateTestStep : CryptographyTest(TestStep.Generate)
class ComputeTestStep : CryptographyTest(TestStep.Compute)
class ValidateTestStep : CryptographyTest(TestStep.Validate)

@OptIn(ExperimentalCoroutinesApi::class)
sealed class CryptographyTest(vararg steps: TestStep) {
    private val steps = steps.toList()
    protected open fun api(metadata: Map<String, String>): Api = HttpApi(metadata)

    @Test
    fun aesCbc() = testIt(aesCbc)

    @Test
    fun digest() = testIt(digest)

    @Test
    fun hmac() = testIt(hmac)

    private fun testIt(suite: TestSuite) = runTest {
        steps.forEach { step ->
            val action = suite.actions[step] ?: run {
                println("No step '$step' for '${suite.algorithm}'")
                return@forEach
            }
            supportedProviders.forEach { provider ->
                val api = api(
                    mapOf(
                        "provider" to provider.name,
                        "platform" to currentPlatform
                    )
                )
                println("START: ${suite.algorithm}, Step: $step | ${api.metadata}")
                action.execute(api, provider)
                println("END:   ${suite.algorithm}, Step: $step | ${api.metadata}")
            }
        }
    }
}
