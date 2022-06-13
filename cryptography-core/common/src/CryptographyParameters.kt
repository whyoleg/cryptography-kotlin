package dev.whyoleg.cryptography

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
