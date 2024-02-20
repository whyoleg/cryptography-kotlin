/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("FunctionName")

package dev.whyoleg.cryptography.providers.webcrypto.internal

// marker interface
internal expect interface Algorithm

internal expect fun Algorithm(name: String): Algorithm

internal expect fun AesKeyGenerationAlgorithm(name: String, length: Int): Algorithm

internal expect fun AesCbcCipherAlgorithm(iv: ByteArray): Algorithm

internal expect fun AesCtrCipherAlgorithm(counter: ByteArray, length: Int): Algorithm

internal expect fun AesGcmCipherAlgorithm(additionalData: ByteArray?, iv: ByteArray, tagLength: Int): Algorithm

internal expect fun HmacKeyAlgorithm(hash: String, length: Int): Algorithm

internal expect fun EcKeyAlgorithm(
    name: String, //ECDSA | ECDH
    namedCurve: String, //P-256, P-384, P-521
): Algorithm

internal expect fun EcdsaSignatureAlgorithm(hash: String): Algorithm

internal expect fun RsaKeyGenerationAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    modulusLength: Int,
    publicExponent: ByteArray,
    hash: String,
): Algorithm

internal expect fun RsaKeyImportAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    hash: String,
): Algorithm

internal expect fun RsaOaepCipherAlgorithm(label: ByteArray?): Algorithm

internal expect fun RsaPssSignatureAlgorithm(saltLength: Int): Algorithm
