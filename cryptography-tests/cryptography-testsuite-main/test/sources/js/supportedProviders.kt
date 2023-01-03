package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.WebCrypto
)
