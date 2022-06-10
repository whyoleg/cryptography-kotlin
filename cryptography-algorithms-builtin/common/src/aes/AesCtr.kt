package dev.whyoleg.cryptography.aes

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

public class AesCtrKeyGenerationParameters(
    keySize: KeySize
) : AesKeyGenerationParameters<AesCtrKey>(keySize)

public interface AesCtrKey : AesKey {
    public val cipher: AesCtrCipher
}

public interface AesCtrCipher : BoxCipher<Unit, AesCtrBox>

public class AesCtrBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext
) : CipherBox(ciphertext)
