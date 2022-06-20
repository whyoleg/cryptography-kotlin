package dev.whyoleg.cryptography

public interface CP {
    public fun <
            BasePrimitive : CryptographyPrimitive,
            Primitive : BasePrimitive,
            Parameters : CryptographyParameters,
            > get(
        algorithm: CryptographyAlgorithm<BasePrimitive, Parameters>,
        id: CryptographyPrimitiveId<Primitive>,
        parameters: Parameters,
    )
}

public sealed class CryptographyProvider {
    public abstract fun <
            BasePrimitive : CryptographyPrimitive,
            Primitive : BasePrimitive,
            Material : CryptographyMaterial,
            Parameters : CryptographyParameters,
            > get(
        primitiveId: CryptographyPrimitiveId<BasePrimitive, Primitive, Material, Parameters>,
        material: Material,
        parameters: Parameters,
    ): Primitive

    public inline fun <
            BasePrimitive : CryptographyPrimitive,
            Primitive : BasePrimitive,
            Material : CryptographyMaterial,
            Parameters : CryptographyParameters,
            > CryptographyPrimitiveFactory<BasePrimitive, Primitive, Material, Parameters, *>.from(
        material: Material,
        parameters: Parameters,
    ): Primitive = get(primitiveId, material, parameters)

    public inline operator fun <
            BasePrimitive : CryptographyPrimitive,
            Primitive : BasePrimitive,
            Material : CryptographyMaterial,
            Parameters : CryptographyParameters,
            Builder,
            > CryptographyPrimitiveFactory<BasePrimitive, Primitive, Material, Parameters, Builder>.invoke(
        material: Material,
        block: Builder.() -> Unit = {},
    ): Primitive = from(material, parametersFactory.invoke(block))


//    public fun <
//            Primitive : CryptographyPrimitive,
//            Parameters : ProviderParameters<Primitive, EmptyMaterial>,
//            > CryptographyProvider.from(
//        parameters: Parameters,
//    ): Primitive = from(EmptyMaterial, parameters)
//
//    //when context receivers will be ready, can be moved out of interface and made inline
//    public /*inline*/ operator fun <
//            Primitive : CryptographyPrimitive,
//            Material : CryptographyMaterial,
//            Parameters : ProviderParameters<Primitive, Material>,
//            Builder,
//            > ProviderParametersFactory<Primitive, Material, Parameters, Builder>.invoke(
//        material: Material,
//        block: Builder.() -> Unit = {},
//    ): Primitive = from(material, Parameters(block))
//
//    //when context receivers will be ready, can be moved out of interface and made inline
//    public /*inline*/ operator fun <
//            Primitive : CryptographyPrimitive,
//            Parameters : ProviderParameters<Primitive, EmptyMaterial>,
//            Builder,
//            > ProviderParametersFactory<Primitive, EmptyMaterial, Parameters, Builder>.invoke(
//        block: Builder.() -> Unit = {},
//    ): Primitive = invoke(EmptyMaterial, block)
}
