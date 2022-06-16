package dev.whyoleg.cryptography

public interface CryptographyProvider {
    public fun <
            Primitive : CryptographyPrimitive,
            Material : CryptographyMaterial,
            Parameters : ProviderParameters<Primitive, Material>
            > from(
        material: Material,
        parameters: Parameters
    ): Primitive

    public fun <
            Primitive : CryptographyPrimitive,
            Parameters : ProviderParameters<Primitive, EmptyMaterial>
            > CryptographyProvider.from(
        parameters: Parameters
    ): Primitive = from(EmptyMaterial, parameters)

    //when context receivers will be ready, can be moved out of interface and made inline
    public /*inline*/ operator fun <
            Primitive : CryptographyPrimitive,
            Material : CryptographyMaterial,
            Parameters : ProviderParameters<Primitive, Material>,
            Builder
            > ProviderParametersFactory<Primitive, Material, Parameters, Builder>.invoke(
        material: Material,
        block: Builder.() -> Unit = {}
    ): Primitive = from(material, Parameters(block))

    //when context receivers will be ready, can be moved out of interface and made inline
    public /*inline*/ operator fun <
            Primitive : CryptographyPrimitive,
            Parameters : ProviderParameters<Primitive, EmptyMaterial>,
            Builder
            > ProviderParametersFactory<Primitive, EmptyMaterial, Parameters, Builder>.invoke(
        block: Builder.() -> Unit = {}
    ): Primitive = invoke(EmptyMaterial, block)
}
