package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface SignAlgorithm : Algorithm
internal sealed external interface VerifyAlgorithm : Algorithm
internal sealed external interface SignatureAlgorithm : SignAlgorithm, VerifyAlgorithm

internal sealed external interface RsaPssParams : SignatureAlgorithm {
    var saltLength: Int
}

internal fun RsaPssParams(saltLength: Int): RsaPssParams = Algorithm("RSA-PSS") {
    this.saltLength = saltLength
}
