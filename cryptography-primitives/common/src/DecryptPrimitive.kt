package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface DecryptPrimitive<C> {
    public fun plaintextSize(context: C, ciphertextSize: BinarySize): BinarySize
    public fun decrypt(context: C, ciphertextInput: BufferView): BufferView
    public fun decrypt(context: C, ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
    public fun decryptFunction(context: C): DecryptFunction
}

public interface BoxDecryptPrimitive<C, B : CipherBox> : DecryptPrimitive<C> {
    public fun plaintextBoxedSize(context: C, ciphertextSize: BinarySize): BinarySize
    public fun decryptBoxed(context: C, ciphertextInput: B): BufferView
    public fun encryptBoxed(context: C, ciphertextInput: B, plaintextOutput: BufferView): BufferView
}

public inline fun <R, C> DecryptPrimitive<C>.decrypt(context: C, block: DecryptFunction.() -> R): R {
    return decryptFunction(context).use(block)
}

public interface DecryptFunction : Closeable {
    public fun plaintextPartSize(ciphertextPartSize: BinarySize): BinarySize
    public fun decryptPart(ciphertextInput: BufferView): BufferView
    public fun decryptPart(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView

    public fun plaintextFinalPartSize(ciphertextFinalPartSize: BinarySize): BinarySize
    public fun decryptFinalPart(ciphertextInput: BufferView): BufferView
    public fun decryptFinalPart(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
}
