package dev.whyoleg.cryptography.webcrypto.external

internal sealed external interface DerivationAlgorithm : Algorithm

internal sealed external interface EcdhDerivationAlgorithm : DerivationAlgorithm {
    var public: CryptoKey
}

internal fun EcdhDerivationAlgorithm(public: CryptoKey): EcdhDerivationAlgorithm = Algorithm("ECDH") {
    this.public = public
}
