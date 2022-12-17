package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import java.security.*
import javax.crypto.*

internal class AesGcmKey(
    private val key: SecretKey,
    private val secureRandom: SecureRandom,
) : AES.GCM.Key() {
    override fun syncCipher(parameters: AES.GCM.CipherParameters): SyncCipher = AesGcmCipher(parameters.tagSize.bits, key, secureRandom)

    override fun asyncCipher(parameters: AES.GCM.CipherParameters): AsyncCipher {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(parameters: AES.GCM.CipherParameters): EncryptFunction {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(parameters: AES.GCM.CipherParameters): DecryptFunction {
        TODO("Not yet implemented")
    }
}

