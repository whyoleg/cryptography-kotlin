package dev.whyoleg.cryptography

import kotlin.jvm.*

//interface in core, implementation in provider: perform some operations
public interface CryptographyPrimitive
public interface CryptographyPrimitiveId<Primitive : CryptographyPrimitive>

public interface CryptographyAlgorithm<BasePrimitive : CryptographyPrimitive, Parameters : CryptographyParameters>

//TODO: make all getters inline in algorithms???

//sync or async, or stream
//public interface CPId<Primitive : CryptographyPrimitive>
//
////simple primitive, Primitive of CPId should extend BasePrimitive
//public interface CPSelector<BasePrimitive : CryptographyPrimitive>
//
//public interface CPA<BasePrimitive : CryptographyPrimitive, Parameters : CryptographyParameters>
//
////name should be unique
////instances in algorithms
//@JvmInline //TODO: name?
//public value class CryptographyPrimitiveAlgorithm<
//        BasePrimitive : CryptographyPrimitive,
//        Material : CryptographyMaterial,
//        Parameters : CryptographyParameters,
//        >(public val name: String)
//
////name should be unique
////instances in algorithms
////used by provider
//public class CryptographyPrimitiveId<
//        BasePrimitive : CryptographyPrimitive,
//        Primitive : BasePrimitive,
//        Material : CryptographyMaterial,
//        Parameters : CryptographyParameters,
//        >(
//    public val algorithm: CryptographyPrimitiveAlgorithm<BasePrimitive, Material, Parameters>,
//    public val classifier: String, //TODO: name, may be get from KClass<Primitive>.simpleName?
//)
//
////instances in algorithms
//public class CryptographyPrimitiveFactory<
//        BasePrimitive : CryptographyPrimitive,
//        Primitive : BasePrimitive,
//        Material : CryptographyMaterial,
//        Parameters : CryptographyParameters,
//        Builder,
//        >(
//    @JvmField
//    @PublishedApi
//    internal val primitiveId: CryptographyPrimitiveId<BasePrimitive, Primitive, Material, Parameters>,
//    @JvmField
//    @PublishedApi
//    internal val parametersFactory: CryptographyParametersFactory<Parameters, Builder>,
//)
//
////instances in algorithms
////used by provider
//public class CryptographyPrimitiveDescriptor<
//        BasePrimitive : CryptographyPrimitive,
//        Material : CryptographyMaterial,
//        Parameters : CryptographyParameters,
//        >
//@PublishedApi
//internal constructor(
//    public val algorithm: CryptographyPrimitiveAlgorithm<BasePrimitive, Material, Parameters>,
//    public val parameters: Parameters,
//)
//
////instances in algorithms
//public class CryptographyPrimitiveDescriptorFactory<
//        BasePrimitive : CryptographyPrimitive,
//        Material : CryptographyMaterial,
//        Parameters : CryptographyParameters,
//        Builder,
//        >(
//    @PublishedApi
//    internal val algorithm: CryptographyPrimitiveAlgorithm<BasePrimitive, Material, Parameters>,
//    @JvmField
//    @PublishedApi
//    internal val parametersFactory: CryptographyParametersFactory<Parameters, Builder>,
//) {
//    public fun from(parameters: Parameters): CryptographyPrimitiveDescriptor<BasePrimitive, Material, Parameters> =
//        CryptographyPrimitiveDescriptor(algorithm, parameters)
//
//    public inline operator fun invoke(block: Builder.() -> Unit = {}): CryptographyPrimitiveDescriptor<BasePrimitive, Material, Parameters> =
//        CryptographyPrimitiveDescriptor(algorithm, parametersFactory.invoke(block))
//}
