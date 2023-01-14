package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.WebCrypto
)
