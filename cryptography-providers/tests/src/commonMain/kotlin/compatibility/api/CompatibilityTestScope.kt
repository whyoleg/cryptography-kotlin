/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility.api

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.tests.api.*

open class CompatibilityTestScope<A : CryptographyAlgorithm>(
    logger: TestLogger,
    context: TestContext,
    provider: CryptographyProvider,
    algorithm: A,
    val api: CompatibilityApi,
) : AlgorithmTestScope<A>(logger, context, provider, algorithm)
