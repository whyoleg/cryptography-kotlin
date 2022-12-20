package dev.whyoleg.cryptography

import kotlin.jvm.*

//TODO: decide on contract, what should be mentioned here
// good candidates: ECDSA, ECDH, DH, AES-CBC, RSA-OAEP
// but what to put for key generation, encoding, decoding - may be it should be some separate thing?
@JvmInline
public value class CryptographyOperationId(public val name: String)

public interface CryptographyOperation {
    //TODO: is it needed here?
    public val engineId: CryptographyEngineId
    public val operationId: CryptographyOperationId
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
    //TODO: rename?
    public abstract fun provideOperation(parameters: P): O
}

public fun <P : CryptographyParameters, O : CryptographyOperation> CryptographyOperationProvider<P, O>.factory(
    operationId: CryptographyOperationId,
    defaultParameters: P,
): CryptographyOperationFactory<P, O> = CryptographyOperationFactory(operationId, defaultParameters, this)
