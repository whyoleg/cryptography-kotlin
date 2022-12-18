package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface Algorithm {
    var name: String
}

internal sealed external interface KeyGenerationAlgorithm : Algorithm
internal sealed external interface SignatureAlgorithm : Algorithm
internal sealed external interface SymmetricKeyGenerationAlgorithm : KeyGenerationAlgorithm
internal sealed external interface HmacKeyGenerationAlgorithm : SymmetricKeyGenerationAlgorithm {
    var hash: String
    var length: Int //TODO - is it needed?
}

internal inline fun <T : Algorithm> Algorithm(name: String, block: T.() -> Unit = {}): T =
    js("{}").unsafeCast<T>().apply {
        this.name = name
        block()
    }

