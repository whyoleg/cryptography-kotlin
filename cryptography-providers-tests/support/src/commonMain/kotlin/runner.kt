/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.*
import kotlinx.coroutines.test.*

private const val enableLogsGlobal = false

fun <A : CryptographyAlgorithm> runTestForEachAlgorithm(
    algorithmId: CryptographyAlgorithmId<A>,
    rootTag: String? = null,
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend AlgorithmTestScope<A>.() -> Unit,
): TestResult = runTest(rootTag, enableLogs) { forEachAlgorithm(algorithmId, block) }

fun runTestForEachProvider(
    rootTag: String? = null,
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend ProviderTestScope.() -> Unit,
): TestResult = runTest(rootTag, enableLogs) { forEachProvider(block) }

fun runTest(
    rootTag: String? = null,
    enableLogs: Boolean = enableLogsGlobal,
    block: suspend TestScope.() -> Unit,
): TestResult = runTest(dispatchTimeoutMs = Long.MAX_VALUE) {
    val logger = TestLogger(enableLogs, rootTag)
    logger.print("PLATFORM: $currentTestPlatform")
    TestScope(logger).block()
}

suspend fun <A : CryptographyAlgorithm> TestScope.forEachAlgorithm(
    algorithmId: CryptographyAlgorithmId<A>,
    block: suspend AlgorithmTestScope<A>.() -> Unit,
): Unit = forEachProvider {
    if (!supports(algorithmId)) return@forEachProvider

    val logger = logger.child(algorithmId.name)
    val algorithm = provider.getOrNull(algorithmId) ?: run {
        logger.print("not supported")
        return@forEachProvider
    }
    logger.print("START")
    AlgorithmTestScope(logger, context, provider, algorithm).block()
    logger.print("COMPLETE")
}

private suspend fun TestScope.forEachProvider(
    block: suspend ProviderTestScope.() -> Unit,
) {
    val errors = mutableListOf<Pair<String, Throwable>>()
    availableProviders.forEach { provider ->
        val logger = logger.child(provider.name)
        try {
            logger.print("START")
            ProviderTestScope(logger, TestContext(provider), provider).block()
            logger.print("COMPLETE")
        } catch (cause: Throwable) {
            logger.print("FAILURE: ${cause.stackTraceToString()}")
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
