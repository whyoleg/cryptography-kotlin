package dev.whyoleg.cryptography.test.step.api

internal actual val currentPlatform: String by lazy {
    val isNodeJs =
        js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()
    when {
        isNodeJs -> "NodeJS"
        else     -> "Browser"
    }
}
