package dev.whyoleg.cryptography

import dev.whyoleg.bignumber.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public sealed interface RsaParameters : CryptographyParameters {
    public val keySize: KeySize
    public val publicExponent: BigInt
}

public sealed interface RsaParametersBuilder<P : RsaParameters> : CryptographyParametersBuilder<P> {
    public fun keySize(value: KeySize)
    public fun publicExponent(value: BigInt)
}

public sealed interface RsaOaepParameters : RsaParameters {
    public val hash: HashParameters
}

public sealed interface RsaOaepParametersBuilder : RsaParametersBuilder<RsaOaepParameters> {
    public fun hash(value: HashParameters)
}

public object RsaOaepParametersFactory : CryptographyParametersFactory<RsaOaepParameters, RsaOaepParametersBuilder>(
    createBuilder = ::RsaOaepParametersImpl,
    build = { it as RsaOaepParameters }
)

private class RsaOaepParametersImpl : RsaOaepParameters, RsaOaepParametersBuilder {
    override var keySize: KeySize = KeySize(1024.bits) //TODO: default
    override var publicExponent: BigInt = BigInt(65537) //TODO: default
    override var hash: HashParameters = Sha.SHA256 //TODO: default

    override fun keySize(value: KeySize) {
        keySize = value
    }

    override fun publicExponent(value: BigInt) {
        publicExponent = value
    }

    override fun hash(value: HashParameters) {
        hash = value
    }
}
