package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface Decryptor {
    public fun plaintextSize(ciphertextSize: Int): Int
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public fun decryptBlocking(ciphertextInput: Buffer): Buffer
}
