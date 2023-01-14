package dev.whyoleg.cryptography.test.step.api

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.api.*

enum class TestStep { Generate, Compute, Validate }

fun interface TestRun {
    suspend fun execute(api: Api, provider: CryptographyProvider)
}

class TestAlgorithm(val name: String, val steps: Map<TestStep, TestRun>)

fun String.testAlgorithm(
    generate: TestRun,
    compute: TestRun? = null,
    validate: TestRun,
) = TestAlgorithm(
    this, buildMap {
        put(TestStep.Generate, generate)
        compute?.let { put(TestStep.Compute, it) }
        put(TestStep.Validate, validate)
    }
)
