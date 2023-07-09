/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.external

import org.khronos.webgl.*

internal sealed external interface KeyAlgorithm : Algorithm
internal sealed external interface KeyGenerationAlgorithm : KeyAlgorithm
internal sealed external interface KeyImportAlgorithm : KeyAlgorithm
internal sealed external interface SymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm
internal sealed external interface AsymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm

internal sealed external interface HmacKeyAlgorithm : SymmetricKeyGenerationAlgorithm, KeyImportAlgorithm {
    var hash: String
    var length: Int
}

internal fun HmacKeyAlgorithm(hash: String, length: Int): HmacKeyAlgorithm = Algorithm("HMAC") {
    this.hash = hash
    this.length = length
}

internal sealed external interface AesKeyGenerationAlgorithm : SymmetricKeyGenerationAlgorithm {
    var length: Int
}

internal fun AesKeyGenerationAlgorithm(name: String, length: Int): AesKeyGenerationAlgorithm =
    Algorithm(name) {
        this.length = length
    }

internal sealed external interface RsaHashedKeyGenerationAlgorithm : AsymmetricKeyGenerationAlgorithm {
    var modulusLength: Int
    var publicExponent: Uint8Array
    var hash: String
}

internal fun RsaHashedKeyGenerationAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    modulusLength: Int,
    publicExponent: ByteArray,
    hash: String,
): RsaHashedKeyGenerationAlgorithm = Algorithm(name) {
    this.modulusLength = modulusLength
    this.publicExponent = publicExponent.unsafeCast<Int8Array>().let {
        Uint8Array(it.buffer, it.byteOffset, it.length)
    }
    this.hash = hash
}

internal sealed external interface RsaHashedKeyImportAlgorithm : KeyImportAlgorithm {
    var hash: String
}

internal fun RsaHashedKeyImportAlgorithm(
    name: String, //RSA-PSS | RSA-OAEP
    hash: String,
): RsaHashedKeyImportAlgorithm = Algorithm(name) {
    this.hash = hash
}

internal sealed external interface EcKeyAlgorithm : AsymmetricKeyGenerationAlgorithm, KeyImportAlgorithm {
    var namedCurve: String
}

internal fun EcKeyAlgorithm(
    name: String, //ECDSA | ECDH
    namedCurve: String, //P-256, P-384, P-521
): EcKeyAlgorithm = Algorithm(name) {
    this.namedCurve = namedCurve
}
