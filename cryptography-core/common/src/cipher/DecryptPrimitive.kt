package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface DecryptPrimitive<C, B : CipherBox> : CryptographyPrimitive {
    public fun plaintextSize(context: C, ciphertextSize: BinarySize): BinarySize
    public fun plaintextBoxedSize(context: C, ciphertextSize: BinarySize): BinarySize

    public fun decrypt(context: C, ciphertextInput: Ciphertext): Plaintext
    public fun decrypt(context: C, ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
    public fun decryptBoxed(context: C, ciphertextInput: B): BufferView
    public fun encryptBoxed(context: C, ciphertextInput: B, plaintextOutput: Plaintext): Plaintext

    public suspend fun decryptSuspend(context: C, ciphertextInput: Ciphertext): Plaintext
    public suspend fun decryptSuspend(context: C, ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
    public suspend fun decryptBoxedSuspend(context: C, ciphertextInput: B): Plaintext
    public suspend fun encryptBoxedSuspend(context: C, ciphertextInput: B, plaintextOutput: Plaintext): Plaintext

    public fun decryptFunction(context: C): DecryptFunction
}

public inline fun <R, C> DecryptPrimitive<C, *>.decrypt(context: C, block: DecryptFunction.() -> R): R {
    return decryptFunction(context).use(block)
}
