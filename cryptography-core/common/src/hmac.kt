package dev.whyoleg.cryptography


public sealed interface HmacParameters : CryptographyParameters {
    public val hash: HashParameters
}

public sealed interface HmacParametersBuilder : CryptographyParametersBuilder<HmacParameters> {
    public fun hash(value: HashParameters)
}

public object HmacParametersFactory : CryptographyParametersFactory<HmacParameters, HmacParametersBuilder>(
    createBuilder = ::HmacParametersImpl,
    build = { it as HmacParameters }
)

private class HmacParametersImpl : HmacParameters, HmacParametersBuilder {
    override var hash: HashParameters = Sha.SHA256

    override fun hash(value: HashParameters) {
        hash = value
    }
}
