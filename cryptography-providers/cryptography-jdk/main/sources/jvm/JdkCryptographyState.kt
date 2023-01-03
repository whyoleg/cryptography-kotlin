package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.provider.*
import java.security.*
import java.util.concurrent.*
import javax.crypto.*

//candidate for context receivers
internal class JdkCryptographyState(
    private val provider: JdkProvider,
    val secureRandom: SecureRandom,
    val adaptor: SuspendAdaptor?,
) {
    suspend inline fun <T> execute(crossinline block: () -> T): T = adaptor?.execute { block() } ?: block()

    private val ciphers: ConcurrentHashMap<String, Pooled<Cipher>> = ConcurrentHashMap()
    private val messageDigests: ConcurrentHashMap<String, Pooled<MessageDigest>> = ConcurrentHashMap()
    private val macs: ConcurrentHashMap<String, Pooled<Mac>> = ConcurrentHashMap()
    private val keyGenerators: ConcurrentHashMap<String, Pooled<KeyGenerator>> = ConcurrentHashMap()

    private inline fun <T> ConcurrentHashMap<String, Pooled<T>>.get(
        algorithm: String,
        crossinline s: (String) -> T,
        crossinline s1: (String, String) -> T,
        crossinline s2: (String, Provider) -> T,
        crossinline init: (T) -> Unit = {}, //TODO: drop?
    ): Pooled<T> = getOrPut(algorithm) {
        val instantiate = when (provider) {
            JdkProvider.Default     -> {
                { s(algorithm).also(init) }
            }
            is JdkProvider.Name     -> {
                { s1(algorithm, provider.provider).also(init) }
            }
            is JdkProvider.Instance -> {
                { s2(algorithm, provider.provider).also(init) }
            }
        }
        Pooled(instantiate)
    }

    fun cipher(algorithm: String): Pooled<Cipher> =
        ciphers.get(algorithm, Cipher::getInstance, Cipher::getInstance, Cipher::getInstance)

    fun messageDigest(algorithm: String): Pooled<MessageDigest> =
        messageDigests.get(algorithm, MessageDigest::getInstance, MessageDigest::getInstance, MessageDigest::getInstance)

    fun mac(algorithm: String): Pooled<Mac> =
        macs.get(algorithm, Mac::getInstance, Mac::getInstance, Mac::getInstance)

    fun keyGenerator(algorithm: String): Pooled<KeyGenerator> =
        keyGenerators.get(algorithm, KeyGenerator::getInstance, KeyGenerator::getInstance, KeyGenerator::getInstance)

}

internal fun CryptographyAlgorithmId<Digest>.hashAlgorithmName(): String = when (this) {
    SHA1   -> "SHA1"
    SHA256 -> "SHA256"
    SHA384 -> "SHA384"
    SHA512 -> "SHA512"
    else   -> throw CryptographyException("Unsupported hash algorithm: $this")
}
