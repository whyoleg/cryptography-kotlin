package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.key.*
import java.security.*
import javax.crypto.KeyGenerator

internal class AesCbcKeyGenerator(
    private val keySizeBits: Int,
    private val secureRandom: SecureRandom,
) : SyncKeyGenerator<AES.CBC.Key> {
    private val keyGenerator: ThreadLocal<KeyGenerator> = threadLocal {
        KeyGenerator.getInstance("AES").also {
            it.init(keySizeBits, secureRandom)
        }
    }

    override fun generateKey(): AES.CBC.Key = AesCbcKey(keyGenerator.get().generateKey(), secureRandom)
}
