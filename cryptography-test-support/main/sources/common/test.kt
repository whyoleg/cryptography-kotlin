package dev.whyoleg.cryptography.test.support

import dev.whyoleg.cryptography.provider.*
import kotlinx.coroutines.test.*
import kotlin.test.*

fun runTestForEachProvider(test: suspend (provider: CryptographyProvider) -> Unit): TestResult = runTest {
    val errors = mutableListOf<Pair<String, Throwable>>()
    println("[TEST] PLATFORM: $currentPlatform")
    availableProviders.forEach { provider ->
        println("[TEST] START PROVIDER: ${provider.name}")
        try {
            test(provider)
            println("[TEST] END PROVIDER: ${provider.name}")
        } catch (cause: Throwable) {
            println("[TEST] FAIL PROVIDER: ${provider.name}\nCause: ${cause.stackTraceToString()}")
            errors += provider.name to cause
        }
    }
    if (errors.isNotEmpty()) fail(
        buildString {
            append("Multiple failed tests:")
            errors.forEach { (providerName, cause) ->
                append("\n - ").append(providerName).append(" Cause:").append(cause::class.simpleName).append(": ").append(cause.message)
            }
        },
        MultipleFailuresException(errors)
    )
}

private class MultipleFailuresException(errors: List<Pair<String, Throwable>>) : Throwable() {
    init {
        errors.forEach { addSuppressed(it.second) }
    }
}
