/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.*

actual val availableProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.WebCrypto
)
