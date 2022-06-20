package dev.whyoleg.cryptography

//implemented in core
public interface CryptographyParameters

public object EmptyParameters : CryptographyParameters, CryptographyParametersFactory<EmptyParameters, Unit>() {
    override fun createBuilder(): Unit = Unit
    override fun build(builder: Unit): EmptyParameters = this
}

//instances in algorithms
public abstract class CryptographyParametersFactory<Parameters : CryptographyParameters, Builder> {
    protected abstract fun createBuilder(): Builder
    protected abstract fun build(builder: Builder): Parameters

    @PublishedApi
    internal fun createBuilderInternal(): Builder = createBuilder()

    @PublishedApi
    internal fun buildInternal(builder: Builder): Parameters = build(builder)

    public inline operator fun invoke(block: Builder.() -> Unit = {}): Parameters {
        val builder = createBuilderInternal()
        builder.block()
        return buildInternal(builder)
    }
}
