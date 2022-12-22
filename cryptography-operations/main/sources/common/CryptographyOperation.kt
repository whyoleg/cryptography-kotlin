package dev.whyoleg.cryptography.operations

import kotlin.jvm.*
import kotlin.reflect.*

//TODO: decide on contract, what should be mentioned here
// good candidates: ECDSA, ECDH, DH, AES-CBC, RSA-OAEP
// but what to put for key generation, encoding, decoding - may be it should be some separate thing?
@JvmInline
public value class CryptographyOperationId(public val name: String)

public interface CryptographyOperation {
    public val operationId: CryptographyOperationId
}

@OptIn(ProviderApi::class)
public class CryptographyOperationFactory<P : CryptographyOperationParameters, O : CryptographyOperation> internal constructor(
    public val operationId: CryptographyOperationId,
    @PublishedApi
    internal val defaultParameters: P,
    private val provider: CryptographyOperationProvider<P, O>,
) {
    public operator fun invoke(parameters: P = defaultParameters): O = provider.provideOperationInternal(parameters)
}

public inline operator fun <P : CryptographyOperationParameters.Copyable<P, B>, B, O : CryptographyOperation> CryptographyOperationFactory<P, O>.invoke(
    block: B.() -> Unit,
): O = invoke(defaultParameters.copy(block))

@ProviderApi
public abstract class CryptographyOperationProvider<P : CryptographyOperationParameters, O : CryptographyOperation> {
    protected abstract fun provideOperation(parameters: P): O

    public fun factory(
        operationId: CryptographyOperationId,
        defaultParameters: P,
    ): CryptographyOperationFactory<P, O> = CryptographyOperationFactory(operationId, defaultParameters, this)

    @PublishedApi
    internal fun provideOperationInternal(parameters: P): O = provideOperation(parameters)
}

@Suppress("FunctionName")
@ProviderApi
public inline fun <P : CryptographyOperationParameters, reified O : CryptographyOperation> NotSupportedProvider(
    description: String? = null,
): CryptographyOperationProvider<P, O> = NotSupportedProvider(O::class, description)

@ProviderApi
public fun <P : CryptographyOperationParameters, O : CryptographyOperation> NotSupportedProvider(
    operationClass: KClass<O>,
    description: String? = null,
): CryptographyOperationProvider<P, O> = NotSupportedProviderImpl(operationClass, description)

@ProviderApi
private class NotSupportedProviderImpl<P : CryptographyOperationParameters, O : CryptographyOperation>(
    private val operationClass: KClass<O>,
    private val description: String?,
) : CryptographyOperationProvider<P, O>() {
    override fun provideOperation(parameters: P): O {
        throw CryptographyOperationNotSupportedException(
            "Operation '${operationClass.simpleName}' is not supported".let { message ->
                if (description != null) "$message: $description" else message
            }
        )
    }
}
