package dev.whyoleg.cryptography.test.support

import dev.whyoleg.cryptography.provider.*
import kotlinx.coroutines.test.*

fun runTestForEachProvider(test: suspend (provider: CryptographyProvider) -> Unit): TestResult = runTest {
    val errors = mutableListOf<Pair<String, Throwable>>()
    println("[TEST] PLATFORM: $currentPlatform")
    availableProviders.forEach { provider ->
        //TODO: provider logger
        println("[TEST|${provider.name}] START")
        try {
            test(provider)
            println("[TEST|${provider.name}] SUCCESS")
        } catch (cause: Throwable) {
            println("[TEST|${provider.name}] FAILURE: ${cause.stackTraceToString()}")
            errors += provider.name to cause
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
