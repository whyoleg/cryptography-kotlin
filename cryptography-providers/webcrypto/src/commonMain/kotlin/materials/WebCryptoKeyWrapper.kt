/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoKeyWrapper<K>(
    val usages: Array<String>,
    val wrap: (CryptoKey) -> K,
)
