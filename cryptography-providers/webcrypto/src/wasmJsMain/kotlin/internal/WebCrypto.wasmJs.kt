/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*

internal actual object WebCrypto {
    private val subtle = getSubtleCrypto()

    actual suspend fun digest(algorithmName: String, data: ByteArray): ByteArray {
        return subtle.digest(algorithmName, data.toInt8Array()).await().toByteArray()
    }

    actual suspend fun encrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.encrypt(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    actual suspend fun decrypt(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.decrypt(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    actual suspend fun sign(algorithm: Algorithm, key: CryptoKey, data: ByteArray): ByteArray {
        return subtle.sign(algorithm, key, data.toInt8Array()).await().toByteArray()
    }

    actual suspend fun verify(algorithm: Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Boolean {
        return subtle.verify(algorithm, key, signature.toInt8Array(), data.toInt8Array()).await().toBoolean()
    }

    actual suspend fun importKey(
        format: String,
        keyData: ByteArray,
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: Array<String>,
    ): CryptoKey {
        val fixedFormat = format.substringAfterLast("-")
        val key = when {
            format == "jwk"          -> jsonParse(keyData.decodeToString())
            format.startsWith("pem") -> keyData.decodeFromPem(
                type = when (fixedFormat) {
                    "pkcs8" -> "PRIVATE KEY"
                    "spki"  -> "PUBLIC KEY"
                    else    -> error("Unsupported format: $fixedFormat")
                }
            ).toInt8Array()
            else                     -> keyData.toInt8Array()
        }

        return subtle.importKey(fixedFormat, key, algorithm, extractable, JsArray<JsString>().also {
            keyUsages.forEachIndexed { index, value ->
                it[index] = value.toJsString()
            }
        }).await()
    }

    actual suspend fun exportKey(format: String, key: CryptoKey): ByteArray {
        val fixedFormat = format.substringAfterLast("-")
        val keyData = subtle.exportKey(fixedFormat, key).await()

        return when {
            format == "jwk"          -> jsonStringify(keyData).encodeToByteArray()
            format.startsWith("pem") -> keyData.unsafeCast<ArrayBuffer>().toByteArray().encodeToPem(
                type = when (fixedFormat) {
                    "pkcs8" -> "PRIVATE KEY"
                    "spki"  -> "PUBLIC KEY"
                    else    -> error("Unsupported format: $fixedFormat")
                }
            )
            else                     -> keyData.unsafeCast<ArrayBuffer>().toByteArray()
        }
    }

    actual suspend fun generateKey(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKey {
        return subtle.generateKey(algorithm, extractable, JsArray<JsString>().also {
            keyUsages.forEachIndexed { index, value ->
                it[index] = value.toJsString()
            }
        }).await()
    }

    actual suspend fun generateKeyPair(algorithm: Algorithm, extractable: Boolean, keyUsages: Array<String>): CryptoKeyPair {
        return subtle.generateKeyPair(algorithm, extractable, JsArray<JsString>().also {
            keyUsages.forEachIndexed { index, value ->
                it[index] = value.toJsString()
            }
        }).await()
    }
}

private fun jsonParse(string: String): JsAny = js("JSON.parse(string)")
private fun jsonStringify(any: JsAny): String = js("JSON.stringify(any)")
