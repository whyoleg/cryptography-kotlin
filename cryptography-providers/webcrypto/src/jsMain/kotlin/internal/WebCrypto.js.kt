/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*

internal actual object WebCrypto {
    private val subtle = getSubtleCrypto()

    actual suspend fun digest(algorithmName: String, data: ByteArray): ByteArray {
        return subtle.digest(algorithmName, data).await().toByteArray()
    }

    actual suspend fun encrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.encrypt(algorithm, key, data).await().toByteArray()
    }

    actual suspend fun decrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.decrypt(algorithm, key, data).await().toByteArray()
    }

    actual suspend fun sign(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.sign(algorithm, key, data).await().toByteArray()
    }

    actual suspend fun verify(algorithm: Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Boolean {
        return subtle.verify(algorithm, key, signature, data).await()
    }

    actual suspend fun importKey(
        format: String,
        keyData: ByteArray,
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): CryptoKey {
        return decodeKey(format, keyData, json = { JSON.parse<Any>(it) }, binary = { it }) { fixedFormat, key ->
            subtle.importKey(fixedFormat, key, algorithm, extractable, keyUsages).await()
        }
    }

    actual suspend fun exportKey(format: String, key: CryptoKey): ByteArray {
        return encodeKey(format, { JSON.stringify(it) }, { it.unsafeCast<ArrayBuffer>().toByteArray() }) { fixedFormat ->
            subtle.exportKey(fixedFormat, key).await()
        }
    }

    actual suspend fun generateKey(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKey {
        return subtle.generateKey(algorithm, extractable, keyUsages).await()
    }

    actual suspend fun generateKeyPair(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKeyPair {
        return subtle.generateKeyPair(algorithm, extractable, keyUsages).await()
    }
}
