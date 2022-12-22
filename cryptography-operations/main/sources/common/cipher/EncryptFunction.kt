package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: Int): Int
    public fun encryptPart(plaintextPartInput: Buffer): Buffer
    public fun encryptPart(plaintextPartInput: Buffer, ciphertextPartOutput: Buffer): Buffer

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: Int): Int
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer): Buffer
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer, ciphertextFinalPartOutput: Buffer): Buffer
}
