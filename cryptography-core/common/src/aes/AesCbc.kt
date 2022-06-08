package dev.whyoleg.cryptography.aes

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

public class AesCbcKeyGenerationParameters(
    keySize: KeySize
) : AesKeyGenerationParameters<AesCbcKey>(keySize)

public interface AesCbcKey : AesKey {
    public fun cipher(
        padding: Boolean
    ): AesCbcCipher
}

public interface AesCbcCipher : BoxCipher<Unit, AesCbcBox>

public object AesCbcKeyImportParameters : AesKeyImportParameters<AesCbcKey>()

public class AesCbcBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
) : CipherBox(ciphertext)
