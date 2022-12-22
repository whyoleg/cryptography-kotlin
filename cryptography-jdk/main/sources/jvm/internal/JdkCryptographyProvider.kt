package dev.whyoleg.cryptography.jdk.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.jdk.internal.*
import dev.whyoleg.cryptography.jdk.internal.aes.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.provider.*
import java.security.*

internal class JdkCryptographyProvider(
    private val state: JdkCryptographyState,
) : CryptographyProvider("JDK") {
    //TODO: use map?
    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> get(identifier: CryptographyAlgorithmIdentifier<A>): A {
        return when (identifier) {
            AES.GCM -> AES.GCM(
                AesGcmKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            AES.CBC -> AES.CBC(
                AesCbcKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            MD5     -> MD5(JdkHasherProvider(state, "MD5"))
            SHA1    -> SHA(JdkHasherProvider(state, "SHA-1"))
            SHA512  -> SHA(JdkHasherProvider(state, "SHA-512"))
            HMAC    -> HMAC(
                HmacKeyGeneratorProvider(state),
                NotSupportedProvider()
            )
            else    -> throw CryptographyAlgorithmNotFoundException(identifier)
        } as A
    }
}
