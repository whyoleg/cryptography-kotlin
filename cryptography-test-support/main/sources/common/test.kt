package dev.whyoleg.cryptography.test.support

import dev.whyoleg.cryptography.provider.*
import kotlinx.coroutines.test.*

fun runTestForEachProvider(
    enableLogs: Boolean = true,
    test: suspend TestLoggingContext.(provider: CryptographyProvider) -> Unit,
): TestResult = runTest {
    println("PLATFORM: $currentPlatform")
    val errors = mutableListOf<Pair<String, Throwable>>()
    availableProviders.forEach { provider ->
        with(TestLoggingContext(enableLogs, provider.name)) {
            log("START")
            try {
                test(provider)
                log("SUCCESS")
            } catch (cause: Throwable) {
                log("FAILURE: ${cause.stackTraceToString()}")
                errors += provider.name to cause
            }
        }
    }
    if (errors.isNotEmpty()) throw MultipleFailuresException(errors)
}

private class MultipleFailuresException(
    errors: List<Pair<String, Throwable>>,
) : AssertionError(
    buildString {
        append("Multiple failed tests:")
        errors.forEach { (providerName, cause) ->
            append("\n - ").append(providerName).append(" failure: ").append(cause::class.simpleName).append(": ").append(cause.message)
        }
    }
) {
    init {
        errors.forEach { addSuppressed(it.second) }
    }
}
