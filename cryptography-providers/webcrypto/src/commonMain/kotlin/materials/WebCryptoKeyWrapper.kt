/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal class WebCryptoKeyWrapper<K : Key>(
    val usages: Array<String>,
    val wrap: (CryptoKey) -> K,
)
