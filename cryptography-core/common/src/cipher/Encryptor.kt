package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*

//context is not encrypted or decrypted but needed for encryption/decryption like associated data in AEAD 
public interface Encryptor<C> {
    public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun encrypt(context: C, plaintextInput: BufferView): BufferView
    public fun encrypt(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
    public fun encryptFunction(context: C): EncryptFunction
}

public interface BoxEncryptor<C, B : CipherBox> : Encryptor<C> {
    public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun encryptBoxed(context: C, plaintextInput: BufferView): B
    public fun encryptBoxed(context: C, plaintextInput: BufferView, ciphertextOutput: B): B
}

public inline fun <R, C> Encryptor<C>.encrypt(context: C, block: EncryptFunction.() -> R): R {
    return encryptFunction(context).use(block)
}

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun encryptPart(plaintextInput: BufferView): BufferView
    public fun encryptPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun encryptFinalPart(plaintextInput: BufferView): BufferView
    public fun encryptFinalPart(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
}
