package dev.whyoleg.cryptography.algorithms.asymmetric

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
        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat = SignatureFormat.RAW,
        ): SignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EC.PrivateKey {
        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>,
            format: SignatureFormat = SignatureFormat.RAW,
        ): SignatureGenerator
    }

    public sealed class SignatureFormat {
        //IEEE P1363 format
        public object RAW : SignatureFormat() {
            override fun toString(): String = "ECDSA.SignatureFormat.RAW"
        }

        //X.509 format
        public object DER : SignatureFormat() {
            override fun toString(): String = "ECDSA.SignatureFormat.DER"
        }
    }
}
