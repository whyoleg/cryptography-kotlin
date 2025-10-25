/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.js.*

internal external interface CryptoKey : JsAny

internal external interface CryptoKeyPair : JsAny {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}

internal val CryptoKey.algorithm: Algorithm get() = keyAlgorithm(this)

@Suppress("UNUSED_PARAMETER")
private fun keyAlgorithm(key: CryptoKey): Algorithm = js("key.algorithm")
