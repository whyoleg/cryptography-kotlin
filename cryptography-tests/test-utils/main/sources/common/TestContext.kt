package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*

open class TestContext(
    val logger: TestLogger,
)

open class ProviderTestContext(
    logger: TestLogger,
    val provider: CryptographyProvider,
) : TestContext(logger)

open class AlgorithmTestContext<A : CryptographyAlgorithm>(
    logger: TestLogger,
    provider: CryptographyProvider,
    val algorithm: A,
) : ProviderTestContext(logger, provider)
