package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.mac.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import javax.crypto.*
import javax.crypto.KeyGenerator

internal class Hmac(
    private val state: JdkCryptographyState,
) : HMAC {
    override fun syncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): SyncKeyGenerator<HMAC.Key> {
        val hashAlgorithm = when (parameters.algorithm.algorithm) {
            SHA1   -> "SHA1"
            SHA512 -> "SHA512"
            else   -> throw CryptographyException("Unsupported hash algorithm: ${parameters.algorithm.algorithm}")
        }
        return HmacKeyGenerator(state, hashAlgorithm)
    }

    override fun asyncKeyGenerator(parameters: HMAC.KeyGeneratorParameters): AsyncKeyGenerator<HMAC.Key> {
        TODO("Not yet implemented")
    }
}

internal class HmacKeyGenerator(
    private val state: JdkCryptographyState,
    hashAlgorithm: String,
) : SyncKeyGenerator<HMAC.Key> {
    private val algorithm = "HMAC$hashAlgorithm"
    private val keyGenerator: ThreadLocal<KeyGenerator> = threadLocal {
        state.provider.keyGenerator(algorithm).apply {
            init(state.secureRandom)
        }
    }

    override fun generateKey(): HMAC.Key = HmacKey(state, keyGenerator.get().generateKey(), algorithm)
}

internal class HmacKey(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val algorithm: String,
) : HMAC.Key {
    override fun syncSignature(parameters: CryptographyParameters.Empty): SyncSignature = JdkMacSignature(state, key, algorithm)

    override fun asyncSignature(parameters: CryptographyParameters.Empty): AsyncSignature {
        TODO("Not yet implemented")
    }

    override fun signFunction(parameters: CryptographyParameters.Empty): SignFunction {
        TODO("Not yet implemented")
    }

    override fun verifyFunction(parameters: CryptographyParameters.Empty): VerifyFunction {
        TODO("Not yet implemented")
    }
}

internal class JdkMacSignature(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    algorithm: String,
) : SyncSignature {
    private val mac = threadLocal { state.provider.mac(algorithm) }

    override val signatureSize: Int get() = mac.get().macLength

    override fun sign(dataInput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        return mac.doFinal(dataInput)
    }

    override fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        val mac = mac.get()
        mac.init(key)
        mac.update(dataInput)
        mac.doFinal(signatureOutput, 0)
        return signatureOutput
    }

    override fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return sign(dataInput).contentEquals(signatureInput)
    }
}
