/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

internal expect object WebCrypto {
    suspend fun digest(algorithmName: String, data: ByteArray): ByteArray

    suspend fun encrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray
    suspend fun decrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray

    suspend fun sign(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray
    suspend fun verify(algorithm: Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Boolean

    suspend fun deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: Int): ByteArray

    suspend fun importKey(
        format: String,
        keyData: ByteArray,
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): CryptoKey

    suspend fun exportKey(format: String, key: CryptoKey): ByteArray

    suspend fun generateKey(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKey

    suspend fun generateKeyPair(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKeyPair
}
