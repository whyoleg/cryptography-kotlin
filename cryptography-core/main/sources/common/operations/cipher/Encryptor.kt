package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.io.*

public interface Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public fun encryptBlocking(plaintextInput: Buffer): Buffer
}
