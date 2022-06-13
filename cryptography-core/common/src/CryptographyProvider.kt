package dev.whyoleg.cryptography

import kotlin.reflect.*

//rename to init and initFromKey, add deriveFromKey? add exchangeKey(DH, ECDH), etc
//decodeKey, etc
public interface CryptographyProvider {
    public infix fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>
            > get(parameters: Parameters): Primitive

    public suspend infix fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>
            > getSuspend(parameters: Parameters): Primitive
}

public fun CryptographyProvider(block: CryptographyProviderBuilder.() -> Unit): CryptographyProvider {
    return CryptographyProviderImpl().apply(block)
}

public sealed interface CryptographyProviderBuilder {

    public fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>
            > provide(
        cls: KClass<Parameters>,
        handle: (parameters: Parameters) -> Primitive
    )
}

public inline fun <
        Primitive : CryptographyPrimitive,
        reified Parameters : CryptographyParameters<Primitive>
        > CryptographyProviderBuilder.provide(
    noinline handle: (parameters: Parameters) -> Primitive
) {
    provide(Parameters::class, handle)
}

@Suppress("UNCHECKED_CAST")
private class CryptographyProviderImpl : CryptographyProvider, CryptographyProviderBuilder {
    private val handlers =
        mutableMapOf<KClass<out CryptographyParameters<*>>, (parameters: CryptographyParameters<*>) -> CryptographyPrimitive>()

    override fun <Primitive : CryptographyPrimitive, Parameters : CryptographyParameters<Primitive>> get(
        parameters: Parameters
    ): Primitive {
        val handler =
            handlers[parameters::class] ?: throw NotSupportedAlgorithmException(parameters::class.simpleName ?: "")

        return handler(parameters) as Primitive
    }

    override fun <Primitive : CryptographyPrimitive, Parameters : CryptographyParameters<Primitive>> provide(
        cls: KClass<Parameters>,
        handle: (parameters: Parameters) -> Primitive
    ) {
        handlers[cls] = handle as (parameters: CryptographyParameters<*>) -> CryptographyPrimitive
    }
}
