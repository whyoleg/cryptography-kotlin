package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface EncryptFunction : CryptographyFunction {
    public fun ciphertextPartSize(plaintextPartSize: BinarySize): BinarySize
    public fun encryptPart(plaintextInput: Plaintext): Ciphertext
    public fun encryptPart(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: BinarySize): BinarySize
    public fun encryptFinalPart(plaintextInput: Plaintext): Ciphertext
    public fun encryptFinalPart(plaintextInput: Plaintext, ciphertextOutput: Ciphertext): Ciphertext
}
