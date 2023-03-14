/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test.utils

import dev.whyoleg.cryptography.apple.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.provider.*

actual val availableProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.Apple,
    CryptographyProvider.Openssl3
)
