package dev.whyoleg.cryptography.random

internal actual fun defaultCryptographyRandom(): CryptographyRandom = WebCryptoCryptographyRandom

private object WebCryptoCryptographyRandom : PlatformRandom() {
    private val crypto = run {
        val isNodeJs =
            js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
        when {
            isNodeJs -> js("eval('require')('node:crypto').webcrypto")
            else     -> js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)")
        }
    }
    private const val maxArraySize = 65536

    override fun fillBytes(array: ByteArray) {
        if (array.size <= maxArraySize) {
            crypto.getRandomValues(array)
            return
        }

        val tempArray = ByteArray(maxArraySize)
        crypto.getRandomValues(tempArray)
        tempArray.copyInto(array)

        var remaining = array.size - maxArraySize
        while (true) when {
            remaining == 0            -> break
            remaining <= maxArraySize -> {
                val last = ByteArray(remaining)
                crypto.getRandomValues(last)
                last.copyInto(array, maxArraySize)
                break
            }
            else                      -> {
                crypto.getRandomValues(tempArray)
                tempArray.copyInto(array)
                remaining -= maxArraySize
            }
        }
    }
}
