package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.key.*
import java.security.*

internal class AesGcm(
    private val secureRandom: SecureRandom,
) : AES.GCM() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> =
        AesGcmKeyGenerator(parameters.size.value.bits, secureRandom)

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }
}

