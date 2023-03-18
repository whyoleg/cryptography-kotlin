/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility.api

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.*

open class CompatibilityTestContext<A : CryptographyAlgorithm>(
    logger: TestLogger,
    provider: CryptographyProvider,
    algorithm: A,
    val api: CompatibilityApi,
) : AlgorithmTestContext<A>(logger, provider, algorithm)
