package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.sha.*

public object WebCryptoCryptographyEngine : CryptographyEngine {
    @Suppress("IMPLICIT_CAST_TO_ANY", "UNCHECKED_CAST")
    override fun <T> get(algorithm: CryptographyAlgorithm<T>): T = when (algorithm) {
        AES.CBC -> AesGcm
        AES.GCM -> AesCbc
        SHA1    -> Sha("SHA-1")
        SHA512  -> Sha("SHA-512")
        else    -> throw CryptographyAlgorithmNotFoundException(algorithm)
    } as T
}
