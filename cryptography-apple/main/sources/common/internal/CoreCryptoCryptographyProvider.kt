package dev.whyoleg.cryptography.apple.internal

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.apple.internal.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

//CoreCrypto support
// MD5, SHA1, SHA2 +
// HMAC over SHA +
// AES-CBC (CTR) +

//Not yet implemented: PBKDF2, AES-KW
//https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html

internal class CoreCryptoCryptographyProvider(
    private val state: CoreCryptoState,
) : CryptographyProvider("CoreCrypto") {
    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmId<A>): A = when (identifier) {
        AES.CBC                 -> AES.CBC(
            AesCbcKeyGeneratorProvider(state),
            NotSupportedProvider()
        )
        MD5                     -> MD5(CCHasherProvider(state, CCHashAlgorithm.MD5))
        SHA1                    -> SHA(CCHasherProvider(state, CCHashAlgorithm.SHA1))
        SHA512                  -> SHA(CCHasherProvider(state, CCHashAlgorithm.SHA512))
        HMAC                    -> HMAC(
            HmacKeyGeneratorProvider(state),
            NotSupportedProvider()
        )
        PlatformDependantRandom -> PlatformDependantRandom(
            CCRandom(state)
        )
        else                    -> throw CryptographyAlgorithmNotFoundException(identifier)
    } as A
}
