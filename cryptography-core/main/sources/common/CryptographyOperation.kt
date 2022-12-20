package dev.whyoleg.cryptography

import kotlin.jvm.*
import kotlin.reflect.*

//TODO: decide on contract, what should be mentioned here
// good candidates: ECDSA, ECDH, DH, AES-CBC, RSA-OAEP
// but what to put for key generation, encoding, decoding - may be it should be some separate thing?
@JvmInline
public value class CryptographyOperationId(public val name: String)

public interface CryptographyOperation {
    //TODO: is it needed here?
//    public val engineId: CryptographyEngineId
//    public val operationId: CryptographyOperationId
}

public class CryptographyOperationFactory<P : CryptographyParameters, O : CryptographyOperation> internal constructor(
    public val operationId: CryptographyOperationId,
    @PublishedApi
    internal val defaultParameters: P,
    private val provider: CryptographyOperationProvider<P, O>,
) {
    public val engineId: CryptographyEngineId get() = provider.engineId
    public operator fun invoke(parameters: P = defaultParameters): O = provider.provideOperation(parameters)
}

public inline operator fun <P : CopyableCryptographyParameters<P, B>, B, O : CryptographyOperation> CryptographyOperationFactory<P, O>.invoke(
    block: B.() -> Unit,
): O = invoke(defaultParameters.copy(block))

//TODO: abstract class?
public abstract class CryptographyOperationProvider<P : CryptographyParameters, O : CryptographyOperation>(
    internal val engineId: CryptographyEngineId,
) {
    //TODO: rename? make protected?
    public abstract fun provideOperation(parameters: P): O

    public fun factory(
        operationId: CryptographyOperationId,
        defaultParameters: P,
    ): CryptographyOperationFactory<P, O> = CryptographyOperationFactory(operationId, defaultParameters, this)
}

public inline fun <P : CryptographyParameters, reified O : CryptographyOperation> NotSupportedProvider(
    engineId: CryptographyEngineId,
    description: String? = null,
): CryptographyOperationProvider<P, O> =
    notSupportedProvider(engineId, O::class, description)

@PublishedApi
internal fun <P : CryptographyParameters, O : CryptographyOperation> notSupportedProvider(
    engineId: CryptographyEngineId,
    operationClass: KClass<O>,
    description: String?,
): CryptographyOperationProvider<P, O> = NotSupportedProvider(engineId, operationClass, description)

private class NotSupportedProvider<P : CryptographyParameters, O : CryptographyOperation>(
    engineId: CryptographyEngineId,
    private val operationClass: KClass<O>,
    private val description: String?,
) : CryptographyOperationProvider<P, O>(engineId) {
    override fun provideOperation(parameters: P): O {
        throw CryptographyOperationNotSupportedException(
            "Operation '${operationClass.simpleName}' is not supported by engine '${engineId.name}'".let { message ->
                if (description != null) "$message: $description" else message
            }
        )
    }
}
