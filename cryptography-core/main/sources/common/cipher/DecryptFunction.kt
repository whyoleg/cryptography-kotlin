package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.io.*

public interface DecryptFunction : Closeable {
    public fun plaintextPartSize(ciphertextPartSize: Int): Int
    public fun decryptPart(ciphertextPartInput: Buffer): Buffer
    public fun decryptPart(ciphertextPartInput: Buffer, plaintextPartOutput: Buffer): Buffer

    public fun plaintextFinalPartSize(ciphertextFinalPartSize: Int): Int
    public fun decryptFinalPart(ciphertextFinalPartInput: Buffer): Buffer
    public fun decryptFinalPart(ciphertextFinalPartInput: Buffer, plaintextFinalPartOutput: Buffer): Buffer
}
