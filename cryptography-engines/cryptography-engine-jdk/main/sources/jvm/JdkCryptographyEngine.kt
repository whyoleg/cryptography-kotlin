package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.jdk.aes.*
import java.security.*

//TODO: add provider support
public class JdkCryptographyEngine(
    private val secureRandom: SecureRandom = SecureRandom(),
) : CryptographyEngine {
    override fun <T> get(algorithm: CryptographyAlgorithm<T>): T = when (algorithm) {
        AES.GCM -> AesGcm(secureRandom) as T
        AES.CBC -> AesCbc(secureRandom) as T
        SHA1    -> Sha("SHA-1") as T
        SHA512  -> Sha("SHA-512") as T
        else    -> throw CryptographyAlgorithmNotFoundException(algorithm)
    }
}
