package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: Int): Int
    public fun encryptPart(plaintextPartInput: Buffer): Buffer
    public fun encryptPart(plaintextPartInput: Buffer, ciphertextPartOutput: Buffer): Buffer

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: Int): Int
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer): Buffer
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer, ciphertextFinalPartOutput: Buffer): Buffer
}
