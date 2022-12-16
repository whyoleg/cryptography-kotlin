package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Decryptor {
    public fun plaintextSize(ciphertextSize: Int): Int
}

public interface SyncDecryptor : Decryptor {
    public fun decrypt(ciphertextInput: Buffer): Buffer
    public fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
}

public interface AsyncDecryptor : Decryptor {
    public suspend fun decrypt(ciphertextInput: Buffer): Buffer
    public suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer
}

