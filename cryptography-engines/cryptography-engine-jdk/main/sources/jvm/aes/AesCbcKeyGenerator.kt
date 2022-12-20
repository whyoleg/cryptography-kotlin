package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.key.*
import javax.crypto.KeyGenerator as JdkKeyGenerator

internal class AesCbcKeyGeneratorProvider(
    private val state: JdkCryptographyState,
) : KeyGeneratorProvider<SymmetricKeyParameters, AES.CBC.Key>(ENGINE_ID) {
    override fun provideOperation(parameters: SymmetricKeyParameters): KeyGenerator<AES.CBC.Key> =
        AesCbcKeyGenerator(state, parameters.size.value.bits)
}

internal class AesCbcKeyGenerator(
    private val state: JdkCryptographyState,
    private val keySizeBits: Int,
) : KeyGenerator<AES.CBC.Key> {
    private val keyGenerator: ThreadLocal<JdkKeyGenerator> = threadLocal {
        state.provider.keyGenerator("AES").apply {
            init(keySizeBits, state.secureRandom)
        }
    }

    override fun generateKeyBlocking(): AES.CBC.Key {
        val key = keyGenerator.get().generateKey()
        return AES.CBC.Key(
            AesCbcCipherProvider(state, key),
            NotSupportedProvider(ENGINE_ID)
        )
    }

    override suspend fun generateKey(): AES.CBC.Key {
        TODO("Not yet implemented")
    }
}
