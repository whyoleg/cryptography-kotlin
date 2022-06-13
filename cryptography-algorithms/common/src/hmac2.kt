package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

public object Hmac :
    CryptographyParametersProvider<
            HmacPrimitive,
            HmacParameters,
            HmacParametersBuilder,
            Hmac.Parameters
            >,
    KeyDecodeParametersProvider<
            SymmetricKeyFormat,
            HmacPrimitive,
            HmacParameters,
            HmacParametersBuilder,
            Hmac.Parameters
            > {
    override val factory: Parameters get() = Parameters
    override val decodeKey: Parameters get() = Parameters

    public object Parameters : CryptographyParametersFactory<HmacParameters, HmacParametersBuilder> {
        override fun createBuilder(): HmacParametersBuilder = HmacParametersImpl()
    }
}

public interface HmacPrimitive :
    MacPrimitive,
    SymmetricKeyPrimitive

public sealed interface HmacParameters :
    CreateParameters<HmacPrimitive>,
    KeyDecodeParameters<SymmetricKeyFormat, HmacPrimitive> {
    public val hash: CryptographyParameters<out HashPrimitive>
}

public sealed interface HmacParametersBuilder : CryptographyParametersBuilder<HmacParameters> {
    public fun hash(value: CreateParameters<out HashPrimitive>)
}

public fun <
        Primitive : HashPrimitive,
        Parameters : CreateParameters<Primitive>,
        Builder : CryptographyParametersBuilder<Parameters>,
        Factory : CryptographyParametersFactory<Parameters, Builder>
        > HmacParametersBuilder.hash(
    provider: CryptographyParametersProvider<Primitive, Parameters, Builder, Factory>,
    configure: Builder.() -> Unit = {}
) {
    val parameters = provider.create(configure)
    hash(parameters)
}

private class HmacParametersImpl : HmacParameters, HmacParametersBuilder {
    override var hash: CreateParameters<out HashPrimitive> = TODO() //Sha256Parameters

    override fun hash(value: CreateParameters<out HashPrimitive>) {
        hash = value
    }

    override fun build(): HmacParameters = this
}

private fun s(provider: CryptographyProvider) {

    val parameters = Hmac.Parameters {

        val parameters = Shake128.Parameters {

        }

        hash(parameters)

        //algorithm
        hash(Shake128) { //builder
            digestSize(128.bits)
        }
    }

    provider.get(parameters)

    provider.get(Hmac)

    provider.get(Hmac) {

    }
}