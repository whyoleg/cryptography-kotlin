package dev.whyoleg.cryptography.aes

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public class AesGcmKeyGenerationParameters(
    keySize: KeySize
) : AesKeyGenerationParameters<AesGcmKey>(keySize)

public interface AesGcmKey : AesKey {
    public fun cipher(
        padding: Boolean,
        tagSize: BinarySize
    ): AesGcmCipher
}

public interface AesGcmCipher : BoxCipher<AssociatedData, AesGcmBox>

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
    public val authTag: AuthTag
) : CipherBox(ciphertext)
