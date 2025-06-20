/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import kotlinx.coroutines.test.*

abstract class AlgorithmTest<A : CryptographyAlgorithm>(
    protected val algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : ProviderTest(provider) {
    fun testWithAlgorithm(
        block: suspend AlgorithmTestScope<A>.() -> Unit,
    ): TestResult = testWithAlgorithm(algorithmId, block)
}
