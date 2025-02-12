package algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import kotlin.jvm.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Ed<PublicK : Ed.PublicKey, PrivateK : Ed.PrivateKey, KP : Ed.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {
    public fun publicKeyDecoder(curve: Curve): KeyDecoder<PublicKey.Format, PublicK>
    public fun privateKeyDecoder(curve: Curve): KeyDecoder<PrivateKey.Format, PrivateK>
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KP>

    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val Ed25519: Curve get() = Curve("Ed25519")
            public val X25519: Curve get() = Curve("X25519")

            public val Ed448: Curve get() = Curve("Ed448")
            public val X448: Curve get() = Curve("X448")
        }
    }

    // Similar key interfaces but with Edwards-specific formats
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey> : Key {
        public val publicKey: PublicK
        public val privateKey: PrivateK
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}
