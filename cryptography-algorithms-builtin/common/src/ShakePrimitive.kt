package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

//public enum class Md : HashParameters {
//    MD2, MD4, MD5;
//}

public object Shake128 : Shake<Shake128Parameters, Shake128ParametersBuilder, Shake128.Parameters> {
    override val create: Parameters get() = Parameters

    public object Parameters : CryptographyParametersFactory<Shake128Parameters, Shake128ParametersBuilder> {
        override fun createBuilder(): Shake128ParametersBuilder = Shake128ParametersImpl()
    }
}

public object Shake256 : Shake<Shake256Parameters, Shake256ParametersBuilder, Shake256.Parameters> {
    override val create: Parameters get() = Parameters

    public object Parameters : CryptographyParametersFactory<Shake256Parameters, Shake256ParametersBuilder> {
        override fun createBuilder(): Shake256ParametersBuilder = Shake256ParametersImpl()
    }
}

public sealed interface Shake<
        Parameters : ShakeParameters,
        Builder : ShakeParametersBuilder<Parameters>,
        Factory : CryptographyParametersFactory<Parameters, Builder>
        > : CreateParametersProvider<HashPrimitive, Parameters, Builder, Factory>

public sealed interface ShakeParameters : CreateParameters<HashPrimitive> {
    public val digestSize: BinarySize
}

public sealed interface Shake128Parameters : ShakeParameters
public sealed interface Shake256Parameters : ShakeParameters

public sealed interface ShakeParametersBuilder<Parameters : ShakeParameters> :
    CryptographyParametersBuilder<Parameters> {
    public fun digestSize(value: BinarySize)
}

public sealed interface Shake128ParametersBuilder : ShakeParametersBuilder<Shake128Parameters>
public sealed interface Shake256ParametersBuilder : ShakeParametersBuilder<Shake256Parameters>

private sealed class ShakeParametersImpl<Parameters : ShakeParameters> :
    ShakeParameters,
    ShakeParametersBuilder<Parameters> {
    override var digestSize: BinarySize = 1.bits //TODO default

    override fun digestSize(value: BinarySize) {
        digestSize = value
    }
}

private class Shake128ParametersImpl :
    ShakeParametersImpl<Shake128Parameters>(),
    Shake128Parameters,
    Shake128ParametersBuilder {
    override fun build(): Shake128Parameters = this
}

private class Shake256ParametersImpl :
    ShakeParametersImpl<Shake256Parameters>(),
    Shake256Parameters,
    Shake256ParametersBuilder {
    override fun build(): Shake256Parameters = this
}

private fun param(parameters: ShakeParameters, provider: CryptographyProvider) {
    val primitive = provider.create(parameters)
    when (parameters) {
        is Shake128Parameters -> {
            provider.create(parameters)
            parameters.algorithm.forCreate {
                digestSize(128.bits)
            }
        }

        is Shake256Parameters -> TODO()
    }
}