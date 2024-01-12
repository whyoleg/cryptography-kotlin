/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

internal actual external interface CryptoKey

internal actual external interface CryptoKeyPair {
    actual val privateKey: CryptoKey
    actual val publicKey: CryptoKey
}

internal actual val CryptoKey.algorithmName: String get() = keyAlgorithmName(this)

@Suppress("UNUSED_PARAMETER")
private fun keyAlgorithmName(key: CryptoKey): String = js("key.algorithm.hash.name").unsafeCast<String>()
