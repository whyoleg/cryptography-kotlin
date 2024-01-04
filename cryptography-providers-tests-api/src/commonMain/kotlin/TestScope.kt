/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import dev.whyoleg.cryptography.*

open class TestScope(
    val logger: TestLogger,
)

open class ProviderTestScope(
    logger: TestLogger,
    val context: TestContext,
    val provider: CryptographyProvider,
) : TestScope(logger)

open class AlgorithmTestScope<A : CryptographyAlgorithm>(
    logger: TestLogger,
    context: TestContext,
    provider: CryptographyProvider,
    val algorithm: A,
) : ProviderTestScope(logger, context, provider)
