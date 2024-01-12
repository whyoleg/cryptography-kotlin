/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import org.khronos.webgl.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = WebCryptoCryptographyRandom

private object WebCryptoCryptographyRandom : AbstractRandom() {
    private const val MAX_ARRAY_SIZE = 65536
    private val crypto: Crypto = getCrypto()
    override fun fillBytes(array: ByteArray) {
        fillBytes(array.unsafeCast<Int8Array>())
    }

    private fun fillBytes(jsArray: Int8Array) {
        val size = jsArray.length
        if (size <= MAX_ARRAY_SIZE) {
            crypto.getRandomValues(jsArray)
        } else {
            var filled = 0
            do {
                val chunkSize = minOf(MAX_ARRAY_SIZE, size - filled)
                crypto.getRandomValues(jsArray.subarray(filled, filled + chunkSize))
                filled += chunkSize
            } while (filled < size)
        }
    }
}

private external interface Crypto {
    fun getRandomValues(array: Int8Array)
}

//language=JavaScript
private fun getCrypto(): Crypto {
    return js(
        code = """
    
        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
        if (isNodeJs) {
            return (eval('require')('node:crypto').webcrypto);
        } else {
            return (window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto);
        }
    
               """
    ).unsafeCast<Crypto>()
}
