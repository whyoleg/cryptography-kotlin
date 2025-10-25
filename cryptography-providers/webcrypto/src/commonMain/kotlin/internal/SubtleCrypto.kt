/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import kotlin.js.*

internal external interface SubtleCrypto {
    fun digest(algorithmName: String, data: Int8Array): Promise<ArrayBuffer>

    fun encrypt(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>
    fun decrypt(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>

    fun sign(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>
    fun verify(algorithm: Algorithm, key: CryptoKey, signature: Int8Array, data: Int8Array): Promise<JsBoolean>

    fun deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: Int): Promise<ArrayBuffer>

    fun importKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        keyData: JsAny, /*JSON if jwk, ArrayBuffer otherwise*/
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: JsArray<JsString>,
    ): Promise<CryptoKey>

    fun exportKey(
        format: String, /*"raw" | "pkcs8" | "spki"*/
        key: CryptoKey,
    ): Promise<JsAny /*JSON if jwk, ArrayBuffer otherwise*/>

    fun generateKey(
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: JsArray<JsString>,
    ): Promise<CryptoKey>

    @JsName("generateKey")
    fun generateKeyPair(
        algorithm: Algorithm,
        extractable: Boolean,
        keyUsages: JsArray<JsString>,
    ): Promise<CryptoKeyPair>
}

private external interface Crypto {
    val subtle: SubtleCrypto?
}

//language=JavaScript
private fun getCrypto(): Crypto? = js("(globalThis ? globalThis.crypto : (window.crypto || window.msCrypto))")

internal fun getSubtleCrypto(): SubtleCrypto = requireNotNull(getCrypto()?.subtle) {
    "WebCrypto API is not available. Check Secure Contexts definition (https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) or report an issue"
}
