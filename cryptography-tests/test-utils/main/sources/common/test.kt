package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.algorithms.*
import kotlinx.coroutines.test.*

private const val enableLogsGlobal = true

fun <A : CryptographyAlgorithm> runTestForEachAlgorithm(
    algorithmId: CryptographyAlgorithmId<A>,
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend AlgorithmTestContext<A>.() -> Unit,
): TestResult = runTestForEachProvider(enableLogs) {
    val algorithm = provider.getOrNull(algorithmId) ?: run {
        logger.log { "Algorithm ${algorithmId.name} is not supported by provider ${provider.name}" }
        return@runTestForEachProvider
    }
    AlgorithmTestContext(logger, provider, algorithm).block()
}

fun runTestForEachProvider(
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend ProviderTestContext.() -> Unit,
): TestResult = runTest {
    println("PLATFORM: $currentPlatform")
    val errors = mutableListOf<Pair<String, Throwable>>()
    availableProviders.forEach { provider ->
        val logger = TestLogger(provider.name, enableLogs)
        try {
            ProviderTestContext(logger, provider).block()
        } catch (cause: Throwable) {
            logger.log { "FAILURE: ${cause.stackTraceToString()}" }
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
