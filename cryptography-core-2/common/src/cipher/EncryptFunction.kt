package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*

public inline fun <R> Encryptor.Stream.encrypt(block: EncryptFunction.() -> R): R {
    return createEncryptFunction().use(block)
}

public inline fun <R, C> Encryptor.WithContext.Stream<C>.encrypt(context: C, block: EncryptFunction.() -> R): R {
    return createEncryptFunction(context).use(block)
}

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun encryptPart(plaintextInput: BufferView): BufferView
    public fun encryptPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun encryptFinalPart(plaintextInput: BufferView): BufferView
    public fun encryptFinalPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
}
