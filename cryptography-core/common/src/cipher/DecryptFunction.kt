package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*

public inline fun <R> Decryptor.Stream.decrypt(block: DecryptFunction.() -> R): R {
    return createDecryptFunction().use(block)
}

public inline fun <R, C> Decryptor.WithContext.Stream<C>.decrypt(context: C, block: DecryptFunction.() -> R): R {
    return createDecryptFunction(context).use(block)
}

public interface DecryptFunction : Closeable {
    public fun plaintextPartSize(ciphertextPartSize: BinarySize): BinarySize
    public fun decryptPart(ciphertextInput: BufferView): BufferView
    public fun decryptPart(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView

    public fun plaintextFinalPartSize(ciphertextFinalPartSize: BinarySize): BinarySize
    public fun decryptFinalPart(ciphertextInput: BufferView): BufferView
    public fun decryptFinalPart(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
}
