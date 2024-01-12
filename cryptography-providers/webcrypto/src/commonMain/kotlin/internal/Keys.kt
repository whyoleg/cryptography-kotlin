/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

internal expect interface CryptoKey

internal expect interface CryptoKeyPair {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}

internal expect val CryptoKey.algorithmName: String
