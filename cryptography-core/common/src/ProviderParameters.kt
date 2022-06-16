package dev.whyoleg.cryptography

public interface ProviderParameters<Primitive : CryptographyPrimitive, Material : CryptographyMaterial>

//implemented in core
public abstract class ProviderParametersFactory<
        Primitive : CryptographyPrimitive,
        Material : CryptographyMaterial,
        Parameters : ProviderParameters<Primitive, Material>,
        Builder,
        >
@PublishedApi
internal constructor() {
    protected abstract fun createBuilder(): Builder
    protected abstract fun build(builder: Builder): Parameters

    @PublishedApi
    internal fun createBuilderInternal(): Builder = createBuilder()

    @PublishedApi
    internal fun buildInternal(builder: Builder): Parameters = build(builder)
}

public inline fun <
        Primitive : CryptographyPrimitive,
        Material : CryptographyMaterial,
        Parameters : ProviderParameters<Primitive, Material>,
        Builder
        > ProviderParametersFactory<Primitive, Material, Parameters, Builder>.Parameters(
    block: Builder.() -> Unit = {}
): Parameters {
    val builder = createBuilderInternal()
    builder.block()
    return buildInternal(builder)
}

public inline fun <
        Primitive : CryptographyPrimitive,
        Material : CryptographyMaterial,
        Parameters : ProviderParameters<Primitive, Material>,
        Builder
        > ProviderParametersFactory(
    crossinline createBuilder: () -> Builder,
    crossinline build: (builder: Builder) -> Parameters
): ProviderParametersFactory<Primitive, Material, Parameters, Builder> =
    object : ProviderParametersFactory<Primitive, Material, Parameters, Builder>() {
        override fun createBuilder(): Builder = createBuilder.invoke()
        override fun build(builder: Builder): Parameters = build.invoke(builder)
    }
