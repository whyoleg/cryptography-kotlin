/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import kotlin.jvm.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EC<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey, KP : EC.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {
    public fun publicKeyDecoder(curve: Curve): KeyDecoder<PublicKey.Format, PublicK>
    public fun privateKeyDecoder(curve: Curve): KeyDecoder<PrivateKey.Format, PrivateK>
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KP>

    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            public val P256: Curve get() = Curve("P-256")
            public val P384: Curve get() = Curve("P-384")
            public val P521: Curve get() = Curve("P-521")
        }
    }

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

            // only uncompressed format is supported
            // format defined in X963: 04 | X | Y
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // SPKI = SubjectPublicKeyInfo
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

            public sealed class DER : Format() {
                // via PrivateKeyInfo from PKCS8
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                // via ECPrivateKey structure / RFC 5915
                public data object SEC1 : DER() {
                    override val name: String get() = "DER/SEC1"
                }
            }

            public sealed class PEM : Format() {
                // via PrivateKeyInfo from PKCS8
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                // via ECPrivateKey structure / RFC 5915
                public data object SEC1 : PEM() {
                    override val name: String get() = "PEM/SEC1"
                }
            }
        }
    }
}
