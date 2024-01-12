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

    suspend fun importKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        keyData: ByteArray, /*JSON if jwk, ArrayBuffer otherwise*/
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): CryptoKey

    suspend fun exportKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        key: CryptoKey,
    ): ByteArray /*JSON if jwk, ArrayBuffer otherwise*/

    suspend fun generateKey(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKey

    suspend fun generateKeyPair(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKeyPair
}
