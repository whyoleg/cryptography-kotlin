package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.jdk.*
import javax.crypto.*

internal class AesGcmKey(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
) : AES.GCM.Key() {
    override fun syncCipher(parameters: AES.GCM.CipherParameters): SyncCipher = AesGcmCipher(state, key, parameters.tagSize.bits)

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

