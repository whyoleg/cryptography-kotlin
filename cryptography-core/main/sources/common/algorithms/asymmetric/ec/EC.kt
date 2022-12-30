package dev.whyoleg.cryptography.algorithms.asymmetric.ec

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.derive.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*
import kotlin.jvm.*

@SubclassOptInRequired(ProviderApi::class)
public interface EC<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {
    public fun publicKeyDecoder(curve: Curve): KeyDecoder<PublicKey.Format, PublicK>
    public fun privateKeyDecoder(curve: Curve): KeyDecoder<PrivateKey.Format, PrivateK>
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KP>

    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P256: Curve get() = Curve("P256")
            public val P384: Curve get() = Curve("P384")
            public val P521: Curve get() = Curve("P521")

            //Curve25519 should be separate
//        public val Curve25519: ECCurve get() = ECCurve("Curve25519")
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey> : Key {
        public val publicKey: PublicK
        public val privateKey: PrivateK
    }

    @SubclassOptInRequired(ProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public sealed class Format : KeyFormat {
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }
}
