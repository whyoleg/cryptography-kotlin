package dev.whyoleg.cryptography.jdk.internal.aes

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.internal.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import javax.crypto.KeyGenerator as JdkKeyGenerator

internal class AesCbcKeyGeneratorProvider(
    private val state: JdkCryptographyState,
) : KeyGeneratorProvider<SymmetricKeyParameters, AES.CBC.Key>() {
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
            NotSupportedProvider()
        )
    }

    override suspend fun generateKey(): AES.CBC.Key {
        return state.execute { generateKeyBlocking() }
    }
}
