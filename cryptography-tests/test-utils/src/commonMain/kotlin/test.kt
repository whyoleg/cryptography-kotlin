/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.algorithms.*
import kotlinx.coroutines.test.*

private const val enableLogsGlobal = false

fun <A : CryptographyAlgorithm> runTestForEachAlgorithm(
    algorithmId: CryptographyAlgorithmId<A>,
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend AlgorithmTestContext<A>.() -> Unit,
): TestResult = runTestForEachProvider(enableLogs) {
    val algorithm = provider.getOrNull(algorithmId) ?: run {
        println("Algorithm ${algorithmId.name} is not supported by ${provider.name} provider")
        return@runTestForEachProvider
    }
    AlgorithmTestContext(logger, provider, algorithm).block()
}

fun runTestForEachProvider(
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend ProviderTestContext.() -> Unit,
): TestResult = runTest(dispatchTimeoutMs = 120_000L) {
    println("PLATFORM: $currentPlatform")
    val errors = mutableListOf<Pair<String, Throwable>>()
    availableProviders.forEach { provider ->
        println("PROVIDER: ${provider.name}")
        val logger = TestLogger(provider.name, enableLogs)
        try {
            ProviderTestContext(logger, provider).block()
        } catch (cause: Throwable) {
            println("FAILURE: ${cause.stackTraceToString()}")
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
