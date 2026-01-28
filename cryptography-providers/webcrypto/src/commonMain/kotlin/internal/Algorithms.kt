/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("FunctionName")

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.js.*

internal external interface Algorithm

internal fun Algorithm(name: String): Algorithm =
    js("({ name: name })")

internal fun AesKeyGenerationAlgorithm(name: String, length: Int): Algorithm =
    js("({ name: name, length: length })")

internal fun AesCbcCipherAlgorithm(iv: ByteArray): Algorithm =
    jsAesCbcCipherAlgorithm(iv.toInt8Array())

private fun jsAesCbcCipherAlgorithm(iv: Int8Array): Algorithm =
    js("({ name: 'AES-CBC', iv: iv })")

internal fun AesCtrCipherAlgorithm(counter: ByteArray, length: Int): Algorithm =
    jsAesCtrCipherAlgorithm(counter.toInt8Array(), length)

private fun jsAesCtrCipherAlgorithm(counter: Int8Array, length: Int): Algorithm =
    js("({ name: 'AES-CTR', counter: counter, length: length })")

internal fun AesGcmCipherAlgorithm(additionalData: ByteArray?, iv: ByteArray, tagLength: Int): Algorithm = when (additionalData) {
    null -> jsAesGcmCipherAlgorithm(iv.toInt8Array(), tagLength)
    else -> jsAesGcmCipherAlgorithm(iv.toInt8Array(), tagLength, additionalData.toInt8Array())
}

private fun jsAesGcmCipherAlgorithm(iv: Int8Array, tagLength: Int): Algorithm =
    js("({ name: 'AES-GCM', iv: iv, tagLength: tagLength })")

private fun jsAesGcmCipherAlgorithm(iv: Int8Array, tagLength: Int, additionalData: Int8Array): Algorithm =
    js("({ name: 'AES-GCM', iv: iv, tagLength: tagLength, additionalData: additionalData })")

internal fun HmacKeyAlgorithm(hash: String, length: Int?): Algorithm = when (length) {
    null -> jsHmacKeyAlgorithm(hash)
    else -> jsHmacKeyAlgorithm(hash, length)
}

private fun jsHmacKeyAlgorithm(hash: String): Algorithm =
    js("({ name: 'HMAC', hash: hash })")

private fun jsHmacKeyAlgorithm(hash: String, length: Int): Algorithm =
    js("({ name: 'HMAC', hash: hash, length: length })")

internal fun EcKeyAlgorithm(name: String, namedCurve: String): Algorithm =
    js("({ name: name, namedCurve: namedCurve })")

internal val Algorithm.ecKeyAlgorithmNamedCurve: String get() = ecKeyAlgorithmNamedCurve(this)

@Suppress("UNUSED_PARAMETER")
private fun ecKeyAlgorithmNamedCurve(algorithm: Algorithm): String = js("algorithm.namedCurve")

internal val Algorithm.algorithmName: String get() = algorithmName(this)

@Suppress("UNUSED_PARAMETER")
private fun algorithmName(algorithm: Algorithm): String = js("algorithm.name")

internal fun EcdsaSignatureAlgorithm(hash: String): Algorithm =
    js("({ name: 'ECDSA', hash: hash })")

internal fun KeyDeriveAlgorithm(name: String, publicKey: CryptoKey): Algorithm =
    js("({ name: name, public: publicKey })")

internal fun Pbkdf2DeriveAlgorithm(hash: String, iterations: Int, salt: ByteArray): Algorithm =
    jsPbkdf2DeriveAlgorithm(hash, iterations, salt.toInt8Array())

private fun jsPbkdf2DeriveAlgorithm(hash: String, iterations: Int, salt: Int8Array): Algorithm =
    js("({ name: 'PBKDF2', hash: hash, iterations: iterations, salt: salt })")

internal fun HkdfDeriveAlgorithm(hash: String, salt: ByteArray, info: ByteArray): Algorithm =
    jsHkdfDeriveAlgorithm(hash, salt.toInt8Array(), info.toInt8Array())

private fun jsHkdfDeriveAlgorithm(hash: String, salt: Int8Array, info: Int8Array): Algorithm =
    js("({ name: 'HKDF', hash: hash, salt: salt, info: info })")

internal fun RsaKeyGenerationAlgorithm(name: String, modulusLength: Int, publicExponent: ByteArray, hash: String): Algorithm {
    val publicExponent2 = publicExponent.toInt8Array().let { Uint8Array(it.buffer, it.byteOffset, it.length) }
    return jsRsaKeyGenerationAlgorithm(name, modulusLength, publicExponent2, hash)
}

private fun jsRsaKeyGenerationAlgorithm(name: String, modulusLength: Int, publicExponent: Uint8Array, hash: String): Algorithm =
    js("({ name: name, modulusLength: modulusLength, publicExponent: publicExponent, hash: hash })")

internal fun RsaKeyImportAlgorithm(name: String, hash: String): Algorithm =
    js("({ name: name, hash: hash })")

internal fun RsaOaepCipherAlgorithm(label: ByteArray?): Algorithm = when (label) {
    null -> jsRsaOaepCipherAlgorithm()
    else -> jsRsaOaepCipherAlgorithm(label.toInt8Array())
}

private fun jsRsaOaepCipherAlgorithm(): Algorithm =
    js("({ name: 'RSA-OAEP' })")

private fun jsRsaOaepCipherAlgorithm(label: Int8Array): Algorithm =
    js("({ name: 'RSA-OAEP', label: label })")

internal fun RsaPssSignatureAlgorithm(saltLength: Int): Algorithm =
    js("({ name: 'RSA-PSS', saltLength: saltLength })")

internal val Algorithm.rsaKeyAlgorithmHashName: String get() = rsaKeyAlgorithmHashName(this)

@Suppress("UNUSED_PARAMETER")
private fun rsaKeyAlgorithmHashName(algorithm: Algorithm): String = js("algorithm.hash.name")
