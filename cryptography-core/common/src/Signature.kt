package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class Signature(public val value: BufferView)

public interface BaseSigner

public interface SyncSigner : BaseSigner {
    public val signatureSize: BinarySize

    public fun sign(input: BufferView): Signature
    public fun sign(input: BufferView, signatureOutput: Signature): Signature
}

public interface AsyncSigner : BaseSigner {
    public val signatureSize: BinarySize

    public suspend fun signAsync(input: BufferView): Signature
    public suspend fun signAsync(input: BufferView, signatureOutput: Signature): Signature
}

public interface StreamSigner : BaseSigner {
    public fun createSignFunction(): SignFunction
}

public inline fun <R> StreamSigner.sign(block: SignFunction.() -> R): R {
    return createSignFunction().use(block)
}

public interface SignFunction : Closeable {
    public val signatureSize: BinarySize

    public fun signPart(input: BufferView)

    public fun signFinalPart(input: BufferView): Signature
    public fun signFinalPart(input: BufferView, signatureOutput: Signature): Signature
}

public interface BaseVerifier

public interface SyncVerifier : BaseVerifier {
    public val signatureSize: BinarySize

    public fun verify(signatureInput: Signature): Boolean
}

public interface AsyncVerifier : BaseVerifier {
    public val signatureSize: BinarySize

    public suspend fun verifyAsync(signatureInput: Signature): Boolean
}

public interface StreamVerifier : BaseVerifier {
    public fun createVerifyFunction(): VerifyFunction
}

public inline fun <R> StreamVerifier.verify(block: VerifyFunction.() -> R): R {
    return createVerifyFunction().use(block)
}

public interface VerifyFunction : Closeable {
    public val signatureSize: BinarySize

    public fun verifyPart(signatureInput: Signature)

    public fun verifyFinalPart(signatureInput: Signature): Boolean
}

public interface BaseMac : BaseSigner, BaseVerifier
public interface SyncMac : BaseMac, SyncSigner, SyncVerifier
public interface AsyncMac : BaseMac, AsyncSigner, AsyncVerifier
public interface StreamMac : BaseMac, StreamSigner, StreamVerifier
