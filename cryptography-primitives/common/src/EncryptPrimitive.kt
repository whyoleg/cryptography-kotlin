package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

//context is not encrypted or decrypted but needed for encryption/decryption like associated data in AEAD 
public interface EncryptPrimitive<C> {
    public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun encrypt(context: C, plaintextInput: BufferView): BufferView
    public fun encrypt(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
    public fun encryptFunction(context: C): EncryptFunction
}

public inline fun <R, C> EncryptPrimitive<C>.encrypt(context: C, block: EncryptFunction.() -> R): R {
    return encryptFunction(context).use(block)
}

public interface BoxEncryptPrimitive<C, B : CipherBox> : EncryptPrimitive<C> {
    public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun encryptBoxed(context: C, plaintextInput: BufferView): B
    public fun encryptBoxed(context: C, plaintextInput: BufferView, ciphertextOutput: B): B
}

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun encryptPart(plaintextInput: BufferView): BufferView
    public fun encryptPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun encryptFinalPart(plaintextInput: BufferView): BufferView
    public fun encryptFinalPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
}
