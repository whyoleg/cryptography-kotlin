package dev.whyoleg.cryptography.random

import org.khronos.webgl.*

internal actual fun defaultCryptographyRandom(): CryptographyRandom = WebCryptoCryptographyRandom

private object WebCryptoCryptographyRandom : PlatformRandom() {
    private const val maxArraySize = 65536
    private val crypto = run {
        val isNodeJs =
            js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
        when {
            isNodeJs -> js("eval('require')('node:crypto').webcrypto")
            else     -> js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)")
        }
    }

    private fun getRandomValues(array: Int8Array) {
        crypto.getRandomValues(array)
    }

    override fun fillBytes(array: ByteArray) {
        val size = array.size
        val jsArray = array.unsafeCast<Int8Array>()
        if (size <= maxArraySize) return getRandomValues(jsArray)
        var filled = 0
        do {
            val chunkSize = minOf(maxArraySize, size - filled)
            getRandomValues(jsArray.subarray(filled, filled + chunkSize))
            filled += chunkSize
        } while (filled < size)
    }
}
