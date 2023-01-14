package dev.whyoleg.cryptography.test.step.api

import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.provider.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.Apple
)
