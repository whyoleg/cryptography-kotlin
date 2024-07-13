/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("FunctionName")

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*

// marker interface
@Suppress("ACTUAL_CLASSIFIER_MUST_HAVE_THE_SAME_SUPERTYPES_AS_NON_FINAL_EXPECT_CLASSIFIER_WARNING")
internal actual external interface Algorithm : JsAny

internal actual fun Algorithm(name: String): Algorithm =
    js("({ name })")

internal actual fun AesKeyGenerationAlgorithm(name: String, length: Int): Algorithm =
    js("({ name, length })")

internal actual fun AesCbcCipherAlgorithm(iv: ByteArray): Algorithm =
    jsAesCbcCipherAlgorithm(iv.toInt8Array())

private fun jsAesCbcCipherAlgorithm(iv: Int8Array): Algorithm =
    js("({ name: 'AES-CBC', iv })")

internal actual fun AesCtrCipherAlgorithm(counter: ByteArray, length: Int): Algorithm =
    jsAesCtrCipherAlgorithm(counter.toInt8Array(), length)

private fun jsAesCtrCipherAlgorithm(counter: Int8Array, length: Int): Algorithm =
    js("({ name: 'AES-CTR', counter, length })")

internal actual fun AesGcmCipherAlgorithm(additionalData: ByteArray?, iv: ByteArray, tagLength: Int): Algorithm = when (additionalData) {
    null -> jsAesGcmCipherAlgorithm(iv.toInt8Array(), tagLength)
    else -> jsAesGcmCipherAlgorithm(iv.toInt8Array(), tagLength, additionalData.toInt8Array())
}

private fun jsAesGcmCipherAlgorithm(iv: Int8Array, tagLength: Int): Algorithm =
    js("({ name: 'AES-GCM', iv: iv, tagLength: tagLength })")

private fun jsAesGcmCipherAlgorithm(iv: Int8Array, tagLength: Int, additionalData: Int8Array): Algorithm =
    js("({ name: 'AES-GCM', iv: iv, tagLength: tagLength, additionalData: additionalData })")

internal actual fun HmacKeyAlgorithm(hash: String, length: Int): Algorithm =
    js("({ name: 'HMAC', hash: hash, length: length })")

internal actual fun EcKeyAlgorithm(name: String, namedCurve: String): Algorithm =
    js("({ name: name, namedCurve: namedCurve })")

internal actual val Algorithm.ecKeyAlgorithmNamedCurve: String get() = ecKeyAlgorithmNamedCurve(this)

@Suppress("UNUSED_PARAMETER")
private fun ecKeyAlgorithmNamedCurve(algorithm: Algorithm): String = js("algorithm.namedCurve")

internal actual fun EcdsaSignatureAlgorithm(hash: String): Algorithm =
    js("({ name: 'ECDSA', hash: hash })")

internal actual fun EcdhKeyDeriveAlgorithm(publicKey: CryptoKey): Algorithm =
    js("({ name: 'ECDH', public: publicKey })")

internal actual fun RsaKeyGenerationAlgorithm(name: String, modulusLength: Int, publicExponent: ByteArray, hash: String): Algorithm {
    val publicExponent2 = publicExponent.toInt8Array().let { Uint8Array(it.buffer, it.byteOffset, it.length) }
    return jsRsaKeyGenerationAlgorithm(name, modulusLength, publicExponent2, hash)
}

private fun jsRsaKeyGenerationAlgorithm(name: String, modulusLength: Int, publicExponent: Uint8Array, hash: String): Algorithm =
    js("({ name: name, modulusLength: modulusLength, publicExponent: publicExponent, hash: hash })")

internal actual fun RsaKeyImportAlgorithm(name: String, hash: String): Algorithm =
    js("({ name: name, hash: hash })")

internal actual fun RsaOaepCipherAlgorithm(label: ByteArray?): Algorithm = when (label) {
    null -> jsRsaOaepCipherAlgorithm()
    else -> jsRsaOaepCipherAlgorithm(label.toInt8Array())
}

private fun jsRsaOaepCipherAlgorithm(): Algorithm =
    js("({ name: 'RSA-OAEP' })")

private fun jsRsaOaepCipherAlgorithm(label: Int8Array): Algorithm =
    js("({ name: 'RSA-OAEP', label: label })")

internal actual fun RsaPssSignatureAlgorithm(saltLength: Int): Algorithm =
    js("({ name: 'RSA-PSS', saltLength: saltLength })")

internal actual val Algorithm.rsaKeyAlgorithmHashName: String get() = rsaKeyAlgorithmHashName(this)

@Suppress("UNUSED_PARAMETER")
private fun rsaKeyAlgorithmHashName(algorithm: Algorithm): String = js("algorithm.hash.name")
