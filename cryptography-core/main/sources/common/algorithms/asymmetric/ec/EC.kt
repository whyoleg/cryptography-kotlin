package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.derive.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*
import kotlin.jvm.*

//TODO: Decide on how to get PublicKey from PrivateKey
//ECDSA and ECDH
@SubclassOptInRequired(ProviderApi::class)
public abstract class EC : CryptographyAlgorithm {
    public companion object : CryptographyAlgorithmId<EC>()

    public abstract val publicKeyDecoder: KeyDecoder<PublicKey.Format, PublicKey>
    public abstract val privateKeyDecoder: KeyDecoder<PrivateKey.Format, PrivateKey>
    public abstract fun keyPairGenerator(curve: Curve): KeyGenerator<KeyPair>

    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P521: Curve get() = Curve("P521")
            public val P384: Curve get() = Curve("P384")
            public val P256: Curve get() = Curve("P256")

            //Curve25519 should be separate
//        public val Curve25519: ECCurve get() = ECCurve("Curve25519")
        }
    }

    //TODO: support key pair import/export
    @SubclassOptInRequired(ProviderApi::class)
    public abstract class KeyPair : Key {
        public abstract val publicKey: PublicKey
        public abstract val privateKey: PrivateKey
    }

    @SubclassOptInRequired(ProviderApi::class)
    public abstract class PublicKey : EncodableKey<PublicKey.Format>, SharedSecretDerivative<PrivateKey.Format> {
        public abstract fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>): SignatureVerifier

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public abstract class PrivateKey : EncodableKey<PrivateKey.Format>, SharedSecretDerivative<PublicKey.Format> {
        //        public abstract val publicKey: PublicKey //TODO: is it needed?
        public abstract fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>): SignatureGenerator

        public sealed class Format : KeyFormat {
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }
}
