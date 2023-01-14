package dev.whyoleg.cryptography.test.suite

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.provider.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.JDK
)
