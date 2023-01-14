package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.derive.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ECDH : EC<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair> {
    override val id: CryptographyAlgorithmId<ECDH> get() = Companion

    public companion object : CryptographyAlgorithmId<ECDH>("ECDH")

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        public fun derivative(): SharedSecretDerivative<EC.PrivateKey.Format>
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun derivative(): SharedSecretDerivative<EC.PublicKey.Format>
    }
}
