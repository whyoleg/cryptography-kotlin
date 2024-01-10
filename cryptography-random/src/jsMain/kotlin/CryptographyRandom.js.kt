/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import org.khronos.webgl.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = WebCryptoCryptographyRandom

private object WebCryptoCryptographyRandom : PlatformRandom() {
    private const val maxArraySize = 65536
    private val crypto: WebCrypto = when {
        isNodeJs() -> nodeJsWebCrypto()
        else       -> browserWebCrypto()
    }

    override fun fillBytes(array: ByteArray) {
        fillBytes(array.unsafeCast<Int8Array>())
    }

    private fun fillBytes(jsArray: Int8Array) {
        val size = jsArray.length
        if (size <= maxArraySize) {
            crypto.getRandomValues(jsArray)
        } else {
            var filled = 0
            do {
                val chunkSize = minOf(maxArraySize, size - filled)
                crypto.getRandomValues(jsArray.subarray(filled, filled + chunkSize))
                filled += chunkSize
            } while (filled < size)
        }
    }
}

private external interface WebCrypto {
    fun getRandomValues(array: Int8Array)
}

private fun isNodeJs(): Boolean =
    js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()

private fun browserWebCrypto(): WebCrypto =
    js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)").unsafeCast<WebCrypto>()

private fun nodeJsWebCrypto(): WebCrypto =
    js("eval('require')('node:crypto').webcrypto").unsafeCast<WebCrypto>()
