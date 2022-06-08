package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

//suspend functions are used in: WebCrypto, remote(GCP, AWS)
//every function can be not supported in some context
//encryptSuspend and encryptBoxedSuspend should be supported everywhere
//boxed mode produces in `ciphertext` only ciphertext, so other encryption parameters should be provided explicitly
//encrypt function works in the same way as not boxed variant
//box functions are not supported

//TODO: better name for *Suspend functions??? Async?
public interface EPrimitive<C, B : CipherBox> {
    public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize

    public fun encrypt(context: C, plaintextInput: BufferView): BufferView
    public fun encrypt(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView

    public suspend fun encryptSuspend(context: C, plaintextInput: BufferView): BufferView
    public suspend fun encryptSuspend(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView

    public fun encryptBoxed(context: C, plaintextInput: BufferView): B
    public fun encryptBoxed(context: C, plaintextInput: BufferView, ciphertextOutput: B): B

    public suspend fun encryptBoxedSuspend(context: C, plaintextInput: BufferView): B
    public suspend fun encryptBoxedSuspend(context: C, plaintextInput: BufferView, ciphertextOutput: B): B

    public fun encryptFunction(context: C): EncryptFunction
}
