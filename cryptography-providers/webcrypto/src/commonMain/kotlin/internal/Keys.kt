/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import dev.whyoleg.cryptography.serialization.pem.*

internal expect interface CryptoKey

internal expect interface CryptoKeyPair {
    val privateKey: CryptoKey
    val publicKey: CryptoKey
}

internal expect val CryptoKey.algorithmName: String

internal inline fun <T> decodeKey(
    format: String,
    keyData: ByteArray,
    json: (string: String) -> T,
    binary: (ByteArray) -> T,
    import: (fixedFormat: String, key: T) -> CryptoKey,
): CryptoKey {
    val fixedFormat = format.substringAfterLast("-")
    val key = whenFormat(
        format = format,
        jwk = { json(keyData.decodeToString()) },
        der = { binary(keyData) },
        pem = { binary(PEM.decode(keyData).ensurePemLabel(pemLabel(fixedFormat)).bytes) },
    )

    return import(fixedFormat, key)
}

internal inline fun <T> encodeKey(
    format: String,
    json: (T) -> String,
    binary: (T) -> ByteArray,
    export: (fixedFormat: String) -> T,
): ByteArray {
    val fixedFormat = format.substringAfterLast("-")
    val keyData = export(fixedFormat)
    return whenFormat(
        format = format,
        jwk = { json(keyData).encodeToByteArray() },
        der = { binary(keyData) },
        pem = { PEM.encodeToByteArray(PemContent(pemLabel(fixedFormat), binary(keyData))) },
    )
}

private inline fun <T> whenFormat(
    format: String,
    jwk: () -> T,
    der: () -> T,
    pem: () -> T,
): T = when {
    format == "jwk"          -> jwk()
    format.startsWith("pem") -> pem()
    else                     -> der()
}

private fun pemLabel(fixedFormat: String): PemLabel = when (fixedFormat) {
    "pkcs8" -> PemLabel.PrivateKey
    "spki"  -> PemLabel.PublicKey
    else    -> error("Unsupported format: $fixedFormat")
}
