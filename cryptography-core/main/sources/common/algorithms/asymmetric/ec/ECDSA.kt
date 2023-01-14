package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDSA : EC<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDSA>("ECDSA")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        public fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>): SignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>): SignatureGenerator
    }
}
