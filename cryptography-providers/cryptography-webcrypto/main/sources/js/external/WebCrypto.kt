package dev.whyoleg.cryptography.webcrypto.external

internal val WebCrypto: Crypto by lazy {
    val isNodeJs =
        js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
    if (isNodeJs) {
        js("eval('require')('node:crypto').webcrypto")
    } else {
        js("(window ? (window.crypto ? window.crypto : window.msCrypto) : self.crypto)")
    }
}
