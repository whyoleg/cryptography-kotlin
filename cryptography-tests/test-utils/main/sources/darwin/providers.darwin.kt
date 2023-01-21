package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.provider.*

actual val availableProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.Apple
)
