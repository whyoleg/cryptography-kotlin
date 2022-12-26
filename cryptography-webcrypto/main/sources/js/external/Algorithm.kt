package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface Algorithm {
    var name: String
}

internal inline fun <T : Algorithm> Algorithm(name: String, block: T.() -> Unit = {}): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }
