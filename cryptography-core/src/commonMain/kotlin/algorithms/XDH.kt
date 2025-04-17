package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.operations.SharedSecretGenerator

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface XDH : Ed<XDH.PublicKey, XDH.PrivateKey, XDH.KeyPair> {
    override val id: CryptographyAlgorithmId<XDH> get() = Companion

    public companion object : CryptographyAlgorithmId<XDH>("XDH")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Ed.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Ed.PublicKey {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Ed.PrivateKey {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>
    }
}
