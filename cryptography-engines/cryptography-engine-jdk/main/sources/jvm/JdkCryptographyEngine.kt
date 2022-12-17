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

    @Suppress("IMPLICIT_CAST_TO_ANY", "UNCHECKED_CAST")
    override fun <T> get(algorithm: CryptographyAlgorithm<T>): T = when (algorithm) {
        AES.GCM -> AesGcm(secureRandom)
        AES.CBC -> AesCbc(secureRandom)
        SHA1    -> Sha("SHA-1")
        SHA512  -> Sha("SHA-512")
        else    -> throw CryptographyAlgorithmNotFoundException(algorithm)
    } as T
}
