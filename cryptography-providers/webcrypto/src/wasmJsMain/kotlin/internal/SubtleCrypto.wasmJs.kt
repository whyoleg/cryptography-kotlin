/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.internal

import org.khronos.webgl.*
import kotlin.js.Promise

internal external interface SubtleCrypto {
    fun digest(algorithmName: String, data: Int8Array): Promise<ArrayBuffer>

    fun encrypt(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>
    fun decrypt(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>

    fun sign(algorithm: Algorithm, key: CryptoKey, data: Int8Array): Promise<ArrayBuffer>
    fun verify(algorithm: Algorithm, key: CryptoKey, signature: Int8Array, data: Int8Array): Promise<JsBoolean>

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

//language=JavaScript
internal fun getSubtleCrypto(): SubtleCrypto {
    js(
        code = """
    
        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
        if (isNodeJs) {
            return (eval('require')('node:crypto').webcrypto).subtle;
        } else {
            return (window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto).subtle;
        }
    
               """
    )
}
