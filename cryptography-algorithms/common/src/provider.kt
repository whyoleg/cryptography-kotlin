package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

//add just create (f.e. hash, random)
//add derive key - !!!!!!!!!!
//add import key - apple keychain, android keychain, remote keystore???, etc.
public sealed interface CryptographyProvider {
    public fun <
            Primitive : Any,
            Format : KeyFormat,
            Parameters : CryptographyParameters,
            Builder : CryptographyParametersBuilder<Parameters>
            > decode(
        marker: PrimitiveDecodeParametersProvider<Primitive, Format, Parameters, Builder>,
        format: KeyFormat,
        input: BufferView,
        build: Builder.() -> Unit = {}
    ): Primitive

    public fun <
            Primitive : Any,
            Parameters : CryptographyParameters,
            Builder : CryptographyParametersBuilder<Parameters>
            > generate(
        marker: PrimitiveGenerateParametersProvider<Primitive, Parameters, Builder>,
        build: Builder.() -> Unit = {}
    ): Primitive
}

public sealed interface CryptographyProviderBuilder {
    public fun <
            Primitive : Any,
            Format : KeyFormat,
            Parameters : CryptographyParameters,
            Builder : CryptographyParametersBuilder<Parameters>
            > onDecode(
        marker: PrimitiveDecodeParametersProvider<Primitive, Format, Parameters, Builder>,
        block: (format: KeyFormat, input: BufferView, parameters: Parameters) -> Primitive,
    )
}

public fun CryptographyProvider(block: CryptographyProviderBuilder.() -> Unit): CryptographyProvider {
    return CryptographyProviderImpl().apply(block)
}

public interface PrimitiveDecodeParametersProvider<
        Primitive : Any,
        Format : KeyFormat,
        Parameters : CryptographyParameters,
        Builder : CryptographyParametersBuilder<Parameters>
        > {
    public val decodeFactory: CryptographyParametersFactory<Parameters, Builder>
}

public interface PrimitiveGenerateParametersProvider<
        Primitive : Any,
        Parameters : CryptographyParameters,
        Builder : CryptographyParametersBuilder<Parameters>
        > {
    public val generateFactory: CryptographyParametersFactory<Parameters, Builder>
}

private class CryptographyProviderImpl : CryptographyProvider, CryptographyProviderBuilder {
    private val decodeMap: MutableMap<PrimitiveDecodeParametersProvider<*, *, *, *>, (KeyFormat, BufferView, CryptographyParameters) -> Any> =
        mutableMapOf()

    override fun <
            Primitive : Any,
            Format : KeyFormat,
            Parameters : CryptographyParameters,
            Builder : CryptographyParametersBuilder<Parameters>
            > onDecode(
        marker: PrimitiveDecodeParametersProvider<Primitive, Format, Parameters, Builder>,
        block: (format: KeyFormat, input: BufferView, parameters: Parameters) -> Primitive
    ) {
        decodeMap[marker] = block as (KeyFormat, BufferView, CryptographyParameters) -> Any
    }

    override fun <
            Primitive : Any,
            Format : KeyFormat,
            Parameters : CryptographyParameters,
            Builder : CryptographyParametersBuilder<Parameters>
            > decode(
        marker: PrimitiveDecodeParametersProvider<Primitive, Format, Parameters, Builder>,
        format: KeyFormat,
        input: BufferView,
        build: Builder.() -> Unit
    ): Primitive {
        val parameters = marker.decodeFactory.create(build)
        val function = decodeMap[marker]!!
        val primitive = function(format, input, parameters)
        return primitive as Primitive
    }
}
