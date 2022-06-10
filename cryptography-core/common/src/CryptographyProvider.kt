package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*
import kotlin.reflect.*

//rename to init and initFromKey, add deriveFromKey? add exchangeKey(DH, ECDH), etc
public interface CryptographyProvider {

    public fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>
            > create(parameters: Parameters): Primitive

    public fun <
            Format : KeyFormat,
            Primitive : KeyPrimitive<Format>,
            Parameters : CryptographyParameters<Primitive>
            > decodeKey(parameters: Parameters, format: Format, input: BufferView): Primitive

    //importKey
    //deriveKey

}

public fun CryptographyProvider(block: CryptographyProviderBuilder.() -> Unit): CryptographyProvider {
    return CryptographyProviderImpl().apply(block)
}

public sealed interface CryptographyProviderBuilder {

    public fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>
            > onCreate(
        cls: KClass<Parameters>,
        handle: (parameters: Parameters) -> Primitive
    )

    public fun <
            Format : KeyFormat,
            Primitive : KeyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForKeyDecode<Format, Primitive, Parameters, Builder>.onDecodeKey(
        cls: KClass<Parameters>,
        handle: (format: Format, input: BufferView, parameters: Parameters) -> Primitive
    )

}

@Suppress("UNCHECKED_CAST")
private class CryptographyProviderImpl : CryptographyProvider(), CryptographyProviderBuilder {
    private val forCreate =
        mutableMapOf<CryptographyAlgorithm.ForCreate<*, *, *>, (parameters: CryptographyParameters<*>) -> CryptographyPrimitive>()
    private val forGenerate =
        mutableMapOf<CryptographyAlgorithm.ForGenerate<*, *, *>, (parameters: CryptographyParameters<*>) -> CryptographyPrimitive>()
    private val forKeyDecode =
        mutableMapOf<CryptographyAlgorithm.ForKeyDecode<*, *, *, *>, (format: KeyFormat, input: BufferView, parameters: CryptographyParameters<*>) -> CryptographyPrimitive>()

    override fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForCreate<Primitive, Parameters, Builder>.getForCreate(
        parameters: Parameters
    ): Primitive {
        return (forCreate.getProvider(this) as (Parameters) -> Primitive)
            .invoke(parameters)
    }

    override fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForCreate<Primitive, Parameters, Builder>.onCreate(
        handle: (parameters: Parameters) -> Primitive
    ) {
        forCreate.putProvider(
            this,
            handle as (CryptographyParameters<*>) -> CryptographyPrimitive
        )
    }

    override fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForGenerate<Primitive, Parameters, Builder>.getForGenerate(
        parameters: Parameters
    ): Primitive {
        return (forGenerate.getProvider(this) as (Parameters) -> Primitive)
            .invoke(parameters)
    }

    override fun <
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForGenerate<Primitive, Parameters, Builder>.onGenerate(
        handle: (parameters: Parameters) -> Primitive
    ) {
        forGenerate.putProvider(
            this,
            handle as (CryptographyParameters<*>) -> CryptographyPrimitive
        )
    }

    override fun <
            Format : KeyFormat,
            Primitive : KeyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForKeyDecode<Format, Primitive, Parameters, Builder>.getForKeyDecode(
        format: Format,
        input: BufferView,
        parameters: Parameters
    ): Primitive {
        return (forKeyDecode.getProvider(this) as (Format, BufferView, Parameters) -> Primitive)
            .invoke(format, input, parameters)
    }

    override fun <
            Format : KeyFormat,
            Primitive : KeyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > CryptographyAlgorithm.ForKeyDecode<Format, Primitive, Parameters, Builder>.onDecodeKey(
        handle: (format: Format, input: BufferView, parameters: Parameters) -> Primitive
    ) {
        forKeyDecode.putProvider(
            this,
            handle as (KeyFormat, BufferView, CryptographyParameters<*>) -> CryptographyPrimitive
        )
    }

    private fun <K, V> Map<K, V>.getProvider(key: K): V {
        return checkNotNull(get(key)) { "Provider is not registered" }
    }

    private fun <K, V> MutableMap<K, V>.putProvider(key: K, value: V) {
        return check(put(key, value) == null) { "Provider already registered" }
    }

}
