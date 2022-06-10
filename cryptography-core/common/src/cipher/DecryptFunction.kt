package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface DecryptFunction : CryptographyFunction {
    public fun plaintextPartSize(ciphertextPartSize: BinarySize): BinarySize
    public fun decryptPart(ciphertextInput: Ciphertext): Plaintext
    public fun decryptPart(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext

    public fun plaintextFinalPartSize(ciphertextFinalPartSize: BinarySize): BinarySize
    public fun decryptFinalPart(ciphertextInput: Ciphertext): Plaintext
    public fun decryptFinalPart(ciphertextInput: Ciphertext, plaintextOutput: Plaintext): Plaintext
}
