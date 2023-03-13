package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.*

actual val availableProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.WebCrypto
)
