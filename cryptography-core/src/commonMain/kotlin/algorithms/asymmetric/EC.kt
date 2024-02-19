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

            // only uncompressed format is supported for now
            // format defined in X963: 04 | X | Y
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public sealed class DER : Format() {
                public companion object SPKI : DER() {
                    override val name: String get() = "DER/SPKI"
                }
            }

            public sealed class PEM : Format() {
                public companion object SPKI : PEM() {
                    override val name: String get() = "PEM/SPKI"
                }
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

            // format defined in X963: 04 | X | Y | K
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public sealed class DER : Format() {
                public companion object PKCS8 : DER() {
                    override val name: String get() = "DER/PKCS8"
                }

                // via ECPrivateKey structure
                public data object SEC1 : DER() {
                    override val name: String get() = "DER/SEC1"
                }
            }

            public sealed class PEM : Format() {
                public companion object PKCS8 : PEM() {
                    override val name: String get() = "PEM/PKCS8"
                }

                public data object SEC1 : PEM() {
                    override val name: String get() = "PEM/SEC1"
                }
            }
        }
    }
}
