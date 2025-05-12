package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EdDSA : Ed<EdDSA.PublicKey, EdDSA.PrivateKey, EdDSA.KeyPair> {
    override val id: CryptographyAlgorithmId<EdDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<EdDSA>("EdDSA")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Ed.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Ed.PublicKey {
        public fun signatureVerifier(): SignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Ed.PrivateKey {
        public fun signatureGenerator(): SignatureGenerator
    }
}
