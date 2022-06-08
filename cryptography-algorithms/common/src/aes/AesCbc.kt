package dev.whyoleg.cryptography.aes

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

//both sync and async
public class AesCbcKeyGenerationParameters(
    keySize: KeySize
) : AesKeyGenerationParameters<AesCbcKey>(keySize)

public interface AesCbcKey : AesKey {
    public fun cipher(
        padding: Boolean
    ): AesCbcCipher
}

//sync only
public interface AesCbcCipher : BoxCipher<Unit, AesCbcBox>

public object AesCbcKeyImportParameters : AesKeyImportParameters<AesCbcKey>()

//both sync and async
public class AesCbcBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
) : CipherBox(ciphertext)
