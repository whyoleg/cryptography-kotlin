package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.derive.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface ECDH : EC<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair> {
    public companion object : CryptographyAlgorithmId<ECDH>()

    @SubclassOptInRequired(ProviderApi::class)
    public interface KeyPair : EC.KeyPair<PublicKey, PrivateKey>

    @SubclassOptInRequired(ProviderApi::class)
    public interface PublicKey : EC.PublicKey {
        public fun derivative(): SharedSecretDerivative<EC.PrivateKey.Format>
    }

    @SubclassOptInRequired(ProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun derivative(): SharedSecretDerivative<EC.PublicKey.Format>
    }
}
