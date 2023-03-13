package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.provider.*

actual val availableProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.Openssl3
)
