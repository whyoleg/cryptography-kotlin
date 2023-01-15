package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.api.*

class TestSuite(
    val algorithm: String,
    val actions: Map<TestStep, TestAction>,
)

fun TestSuite(
    algorithm: String,
    generate: TestAction,
    compute: TestAction? = null,
    validate: TestAction,
): TestSuite = TestSuite(algorithm, buildMap {
    put(TestStep.Generate, generate)
    compute?.let { put(TestStep.Compute, it) }
    put(TestStep.Validate, validate)
})

enum class TestStep { Generate, Compute, Validate }

fun interface TestAction {
    suspend fun execute(api: Api, provider: CryptographyProvider)
}

