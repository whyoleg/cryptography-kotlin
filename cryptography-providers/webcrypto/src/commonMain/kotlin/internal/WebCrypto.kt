/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.js.*
import kotlin.text.decodeToString
import kotlin.text.encodeToByteArray

internal object WebCrypto {
    private val subtle = getSubtleCrypto()


    suspend fun digest(algorithmName: String, data: ByteArray): ByteArray {
        return subtle.digest(algorithmName, data.toInt8Array()).await().toByteArray()
    }

    suspend fun encrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.encrypt(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    suspend fun decrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.decrypt(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    suspend fun sign(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.sign(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    suspend fun verify(algorithm: Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Boolean {
        return subtle.verify(algorithm, key, signature.toInt8Array(), data.toInt8Array()).await().toBoolean()
    }

    suspend fun deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: Int): ByteArray {
        return subtle.deriveBits(algorithm, baseKey, length).await().toByteArray()
    }

    suspend fun importKey(
        format: String,
        keyData: ByteArray,
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): CryptoKey {
        val key = when (format) {
            "jwk" -> jsonParse(keyData.decodeToString())
            else  -> keyData.toInt8Array()
        }
        return subtle.importKey(format, key, algorithm, extractable, keyUsages.toJsArray()).await()
    }

    suspend fun exportKey(format: String, key: CryptoKey): ByteArray {
        val keyData = subtle.exportKey(format, key).await()
        return when (format) {
            "jwk" -> jsonStringify(keyData).encodeToByteArray()
            else  -> keyData.unsafeCast<ArrayBuffer>().toByteArray()
        }
    }

    suspend fun generateKey(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKey {
        return subtle.generateKey(algorithm, extractable, keyUsages.toJsArray()).await()
    }

    suspend fun generateKeyPair(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKeyPair {
        return subtle.generateKeyPair(algorithm, extractable, keyUsages.toJsArray()).await()
    }
}

private fun jsonParse(string: String): JsAny = js("JSON.parse(string)")
private fun jsonStringify(any: JsAny): String = js("JSON.stringify(any)")
