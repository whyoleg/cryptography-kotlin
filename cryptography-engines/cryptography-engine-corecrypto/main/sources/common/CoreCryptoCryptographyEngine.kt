package dev.whyoleg.cryptography.corecrypto

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.engine.*

public object CoreCryptoCryptographyEngine : CryptographyEngine {

    @Suppress("IMPLICIT_CAST_TO_ANY", "UNCHECKED_CAST")
    override fun <T> get(id: CryptographyAlgorithmIdentifier<T>): T = when (id) {
        AES.CBC -> AesCbc
//        SHA1    -> Sha("SHA-1")
        SHA512  -> Sha512
        HMAC    -> Hmac
        else    -> throw CryptographyAlgorithmNotFoundException(id)
    } as T
}

private fun CryptographyEngineBuilder.test() {
    register(AES.CBC) {
        aesCbc()
    }
}
