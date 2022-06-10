package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.key.*

public interface CryptographyParameters<Primitive : CryptographyPrimitive>

public interface CryptographyParametersBuilder<Parameters : CryptographyParameters<*>> {
    public fun build(): Parameters //validation can be done here
}

public interface CryptographyParametersFactory<
        Parameters : CryptographyParameters<*>,
        Builder : CryptographyParametersBuilder<Parameters>
        > {
    public fun createBuilder(): Builder
}

public inline operator fun <
        Parameters : CryptographyParameters<*>,
        Builder : CryptographyParametersBuilder<Parameters>
        > CryptographyParametersFactory<Parameters, Builder>.invoke(
    block: Builder.() -> Unit
): Parameters {
    return createBuilder().apply(block).build()
}

public interface CreateParameters<
        Primitive : CryptographyPrimitive
        > : CryptographyParameters<Primitive>

public interface KeyDecodeParameters<
        Format : KeyFormat,
        Primitive : KeyPrimitive<Format>,
        > : CryptographyParameters<Primitive>


public interface CreateParametersProvider<
        Primitive : CryptographyPrimitive,
        Parameters : CreateParameters<Primitive>,
        Builder : CryptographyParametersBuilder<Parameters>,
        Factory : CryptographyParametersFactory<Parameters, Builder>
        > {
    public val create: Factory
}

public interface KeyDecodeParametersProvider<
        Format : KeyFormat,
        Primitive : KeyPrimitive<Format>,
        Parameters : KeyDecodeParameters<Format, Primitive>,
        Builder : CryptographyParametersBuilder<Parameters>,
        Factory : CryptographyParametersFactory<Parameters, Builder>
        > {
    public val decodeKey: Factory
}

public inline fun <
        Primitive : CryptographyPrimitive,
        Parameters : CreateParameters<Primitive>,
        Builder : CryptographyParametersBuilder<Parameters>,
        Factory : CryptographyParametersFactory<Parameters, Builder>
        > CryptographyProvider.create(
    provider: CreateParametersProvider<Primitive, Parameters, Builder, Factory>,
    configure: Builder.() -> Unit = {}
): Primitive = create(provider.create(configure))
