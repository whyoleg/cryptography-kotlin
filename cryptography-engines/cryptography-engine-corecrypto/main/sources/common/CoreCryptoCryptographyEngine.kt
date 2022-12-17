package dev.whyoleg.cryptography.corecrypto

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.algorithms.sha.*

public object CoreCryptoCryptographyEngine : CryptographyEngine {

    @Suppress("IMPLICIT_CAST_TO_ANY", "UNCHECKED_CAST")
    override fun <T> get(algorithm: CryptographyAlgorithm<T>): T = when (algorithm) {
        AES.CBC -> AesCbc
//        SHA1    -> Sha("SHA-1")
        SHA512  -> Sha512
        else    -> throw CryptographyAlgorithmNotFoundException(algorithm)
    } as T
}
