package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.sha.*

public object WebCryptoCryptographyEngine : CryptographyEngine {
    override fun <T> get(algorithm: CryptographyAlgorithm<T>): T = when (algorithm) {
        AES.GCM -> AesGcm as T
        SHA1    -> Sha("SHA-1") as T
        SHA512  -> Sha("SHA-512") as T
        else    -> throw CryptographyAlgorithmNotFoundException(algorithm)
    }
}
