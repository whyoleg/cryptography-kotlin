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

    override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isEmpty()) return array

        crypto.getRandomValues(array)
        return array
    }
}
