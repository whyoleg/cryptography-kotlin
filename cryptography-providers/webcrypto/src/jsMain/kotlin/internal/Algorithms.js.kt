/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("FunctionName", "UNUSED_VARIABLE")

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*

// marker interface
internal actual external interface Algorithm

internal actual fun Algorithm(name: String): Algorithm =
    js("{ name: name }").unsafeCast<Algorithm>()

internal actual fun AesKeyGenerationAlgorithm(name: String, length: Int): Algorithm =
    js("{ name: name, length: length }").unsafeCast<Algorithm>()

internal actual fun AesCbcCipherAlgorithm(iv: ByteArray): Algorithm =
    js("{ name: 'AES-CBC', iv: iv }").unsafeCast<Algorithm>()

internal actual fun AesCtrCipherAlgorithm(counter: ByteArray, length: Int): Algorithm =
    js("{ name: 'AES-CTR', counter: counter, length: length }").unsafeCast<Algorithm>()

internal actual fun AesGcmCipherAlgorithm(additionalData: ByteArray?, iv: ByteArray, tagLength: Int): Algorithm {
    return when (additionalData) {
        null -> js("{ name: 'AES-GCM', iv: iv, tagLength: tagLength }")
        else -> js("{ name: 'AES-GCM', iv: iv, tagLength: tagLength, additionalData: additionalData }")
    }.unsafeCast<Algorithm>()
}

internal actual fun HmacKeyAlgorithm(hash: String, length: Int?): Algorithm {
    return when (length) {
        null -> js("{ name: 'HMAC', hash: hash }")
        else -> js("{ name: 'HMAC', hash: hash, length: length }")
    }.unsafeCast<Algorithm>()
}

internal actual fun EcKeyAlgorithm(name: String, namedCurve: String): Algorithm =
    js("{ name: name, namedCurve: namedCurve }").unsafeCast<Algorithm>()

internal actual val Algorithm.ecKeyAlgorithmNamedCurve: String get() = ecKeyAlgorithmNamedCurve(this)

@Suppress("UNUSED_PARAMETER")
private fun ecKeyAlgorithmNamedCurve(algorithm: Algorithm): String = js("algorithm.namedCurve").unsafeCast<String>()

internal actual fun EcdsaSignatureAlgorithm(hash: String): Algorithm =
    js("{ name: 'ECDSA', hash: hash }").unsafeCast<Algorithm>()

internal actual fun EcdhKeyDeriveAlgorithm(publicKey: CryptoKey): Algorithm =
    js("{ name: 'ECDH', public: publicKey }").unsafeCast<Algorithm>()

internal actual fun KeyDeriveAlgorithm(name: String, publicKey: CryptoKey): Algorithm =
    js("{ name: name, public: publicKey }").unsafeCast<Algorithm>()

internal actual fun Pbkdf2DeriveAlgorithm(hash: String, iterations: Int, salt: ByteArray): Algorithm =
    js("{ name: 'PBKDF2', hash: hash, iterations: iterations, salt: salt }").unsafeCast<Algorithm>()

internal actual fun HkdfDeriveAlgorithm(hash: String, salt: ByteArray, info: ByteArray): Algorithm =
    js("{ name: 'HKDF', hash: hash, salt: salt, info: info }").unsafeCast<Algorithm>()

internal actual fun RsaKeyGenerationAlgorithm(name: String, modulusLength: Int, publicExponent: ByteArray, hash: String): Algorithm {
    val publicExponent2 = publicExponent.toInt8Array().let { Uint8Array(it.buffer, it.byteOffset, it.length) }
    return js("{ name: name, modulusLength: modulusLength, publicExponent: publicExponent2, hash: hash }").unsafeCast<Algorithm>()
}

internal actual fun RsaKeyImportAlgorithm(name: String, hash: String): Algorithm =
    js("{ name: name, hash: hash }").unsafeCast<Algorithm>()

internal actual fun RsaOaepCipherAlgorithm(label: ByteArray?): Algorithm = when (label) {
    null -> js("{ name: 'RSA-OAEP' }")
    else -> js("{ name: 'RSA-OAEP', label: label }")
}.unsafeCast<Algorithm>()

internal actual fun RsaPssSignatureAlgorithm(saltLength: Int): Algorithm =
    js("{ name: 'RSA-PSS', saltLength: saltLength }").unsafeCast<Algorithm>()

internal actual val Algorithm.rsaKeyAlgorithmHashName: String get() = rsaKeyAlgorithmHashName(this)

@Suppress("UNUSED_PARAMETER")
private fun rsaKeyAlgorithmHashName(algorithm: Algorithm): String = js("algorithm.hash.name").unsafeCast<String>()

internal actual val Algorithm.algorithmName: String get() = algorithmName(this)

@Suppress("UNUSED_PARAMETER")
private fun algorithmName(algorithm: Algorithm): String = js("algorithm.name").unsafeCast<String>()
