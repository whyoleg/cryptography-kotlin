/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.webcrypto.external

internal external interface Crypto {
    val subtle: SubtleCrypto
}
