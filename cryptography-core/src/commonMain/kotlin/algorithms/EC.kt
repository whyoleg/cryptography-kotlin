/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

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

            public val secp256k1: Curve get() = Curve("secp256k1")

            // Brainpool curves (used in European standards and some government applications)
            public val brainpoolP256r1: Curve get() = Curve("brainpoolP256r1")
            public val brainpoolP384r1: Curve get() = Curve("brainpoolP384r1")
            public val brainpoolP512r1: Curve get() = Curve("brainpoolP512r1")
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

            public sealed class RAW : Format() {

                // uncompressed format: 0x04 | X | Y
                public companion object Uncompressed : RAW() {
                    override val name: String get() = "RAW"
                }

                // compressed format: 0x02 | X (odd Y)
                //                    0x03 | X (even Y)
                public data object Compressed : RAW() {
                    override val name: String get() = "RAW/COMPRESSED"
                }
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

            // just `secret` value
            public data object RAW : Format() {
                override val name: String get() = "RAW"
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
