/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto

import dev.whyoleg.cryptography.*

internal fun nonBlocking(): Nothing = throw CryptographyException("Only non-blocking(suspend) calls are supported in WebCrypto")
