package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import javax.crypto.KeyGenerator as JdkKeyGenerator

internal class HmacKeyGeneratorProvider(
    private val state: JdkCryptographyState,
) : KeyGeneratorProvider<HMAC.KeyGeneratorParameters, HMAC.Key>(ENGINE_ID) {
    override fun provideOperation(parameters: HMAC.KeyGeneratorParameters): KeyGenerator<HMAC.Key> {
        val hashAlgorithm = when (parameters.digestIdentifier) {
            SHA1   -> "SHA1"
            SHA512 -> "SHA512"
            else   -> throw CryptographyException("Unsupported hash algorithm: ${parameters.digestIdentifier}")
        }
        return HmacKeyGenerator(state, hashAlgorithm)
    }
}

internal class HmacKeyGenerator(
    private val state: JdkCryptographyState,
    hashAlgorithm: String,
) : KeyGenerator<HMAC.Key> {
    private val algorithm = "HMAC$hashAlgorithm"
    private val keyGenerator: ThreadLocal<JdkKeyGenerator> = threadLocal {
        state.provider.keyGenerator(algorithm).apply {
            init(state.secureRandom)
        }
    }

    override fun generateKeyBlocking(): HMAC.Key {
        val key = keyGenerator.get().generateKey()
        return HMAC.Key(
            JdkMacSignatureProvider(state, key, algorithm),
            NotSupportedProvider(ENGINE_ID)
        )
    }

    override suspend fun generateKey(): HMAC.Key {
        return state.execute { generateKeyBlocking() }
    }
}
