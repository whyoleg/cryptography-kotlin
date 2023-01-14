package dev.whyoleg.cryptography.test.step.api

import dev.whyoleg.cryptography.test.client.*
import dev.whyoleg.cryptography.test.step.api.algorithms.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
abstract class CryptographyTest(
    private val step: TestStep,
) {
    @Test
    fun aesCbc() = testIt(aesCbc)

    private fun testIt(algorithm: TestAlgorithm) = runTest {
        val run = algorithm.steps[step] ?: run {
            println("No step '$step' for '${algorithm.name}'")
            return@runTest
        }
        supportedProviders.forEach { provider ->
            val api = HttpApi(
                mapOf(
                    "provider" to provider.name,
                    "platform" to currentPlatform
                )
            )
            println("START: ${algorithm.name}, Step: $step, Provider: ${provider.name}, Platform: $currentPlatform")
            run.execute(api, provider)
            println("END:   ${algorithm.name}, Step: $step, Provider: ${provider.name}, Platform: $currentPlatform")
        }
    }
}
