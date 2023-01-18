package dev.whyoleg.cryptography.test.support

actual val currentPlatform: String by lazy {
    val isNodeJs =
        js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
    when {
        isNodeJs -> "JS(NodeJS)"
        else     -> "JS(Browser)"
    }
}
