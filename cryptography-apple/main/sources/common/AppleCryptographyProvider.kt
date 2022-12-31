package dev.whyoleg.cryptography.apple

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.random.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.apple.algorithms.*
import dev.whyoleg.cryptography.apple.internal.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*

//CoreCrypto support
// MD5, SHA1, SHA2 +
// HMAC over SHA +
// AES-CBC (CTR) +

//Not yet implemented: PBKDF2, AES-KW
//https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html

public val CryptographyProvider.Companion.Apple: CryptographyProvider by lazy(CryptographyProvider.Companion::Apple)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.Apple(
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = AppleCryptographyProvider(AppleState(adaptor))

internal class AppleCryptographyProvider(
    private val state: AppleState,
) : CryptographyProvider("CoreCrypto") {
    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        PlatformDependantRandom -> CCRandom(state)
        MD5                     -> CCDigest(state, CCHashAlgorithm.MD5)
        SHA1                    -> CCDigest(state, CCHashAlgorithm.SHA1)
        SHA256                  -> CCDigest(state, CCHashAlgorithm.SHA256)
        SHA384                  -> CCDigest(state, CCHashAlgorithm.SHA384)
        SHA512                  -> CCDigest(state, CCHashAlgorithm.SHA512)
        HMAC                    -> CCHmac(state, CCRandom(state)) //TODO
//        AES.CBC                 -> AES.CBC(
//            AesCbcKeyGeneratorProvider(state),
//            NotSupportedProvider()
//        )
        else                    -> throw CryptographyAlgorithmNotFoundException(identifier)
    } as A?
}
