package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface Encryptor {
    public fun ciphertextSize(plaintextSize: Int): Int
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}
