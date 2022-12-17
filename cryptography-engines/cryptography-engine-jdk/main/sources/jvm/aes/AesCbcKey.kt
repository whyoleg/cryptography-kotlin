package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import java.security.*
import javax.crypto.*

internal class AesCbcKey(
    private val key: SecretKey,
    private val secureRandom: SecureRandom,
) : AES.CBC.Key() {
    override fun syncCipher(parameters: AES.CBC.CipherParameters): SyncCipher = AesCbcCipher(parameters.padding, key, secureRandom)

    override fun asyncCipher(parameters: AES.CBC.CipherParameters): AsyncCipher {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(parameters: AES.CBC.CipherParameters): EncryptFunction {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(parameters: AES.CBC.CipherParameters): DecryptFunction {
        TODO("Not yet implemented")
    }
}
