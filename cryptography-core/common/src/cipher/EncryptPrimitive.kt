package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

//suspend functions are used in: WebCrypto, remote(GCP, AWS)
//every function can be not supported in some context
//encryptSuspend and encryptBoxedSuspend should be supported everywhere
//boxed mode produces in `ciphertext` only ciphertext, so other encryption parameters should be provided explicitly
//encrypt function works in the same way as not boxed variant
//box functions are not supported
//context is not encrypted or decrypted but needed for encryption/decryption like associated data in AEAD

//TODO: better name for *Suspend functions??? Async?
public interface EncryptPrimitive<C, B : CipherBox> : CryptographyPrimitive {
    public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
    public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize

    public fun encrypt(context: C, plaintextInput: Plaintext): Ciphertext
    public fun encrypt(context: C, plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
    public fun encryptBoxed(context: C, plaintextInput: Plaintext): B
    public fun encryptBoxed(context: C, plaintextInput: Plaintext, ciphertextOutput: B): B

    public suspend fun encryptSuspend(context: C, plaintextInput: Plaintext): Ciphertext
    public suspend fun encryptSuspend(context: C, plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
    public suspend fun encryptBoxedSuspend(context: C, plaintextInput: Plaintext): B
    public suspend fun encryptBoxedSuspend(context: C, plaintextInput: Plaintext, ciphertextOutput: B): B

    public fun encryptFunction(context: C): EncryptFunction
}

public inline fun <R, C> EncryptPrimitive<C, *>.encrypt(context: C, block: EncryptFunction.() -> R): R {
    return encryptFunction(context).use(block)
}
