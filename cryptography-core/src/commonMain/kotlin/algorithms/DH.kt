/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import kotlin.jvm.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun publicKeyDecoder(parameters: Parameters): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(parameters: Parameters): KeyDecoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(parameters: Parameters): KeyGenerator<KeyPair>

    public fun parametersDecoder(): KeyDecoder<Parameters.Format, Parameters>
    public fun parametersGenerator(keySize: Int = 2048): KeyGenerator<Parameters>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : EncodableKey<Parameters.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // DER = Distinguished Encoding Rules
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM = Privacy-Enhanced Mail
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Key {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // DER = Distinguished Encoding Rules (SPKI = SubjectPublicKeyInfo)
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM = Privacy-Enhanced Mail (SPKI = SubjectPublicKeyInfo)
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // DER = Distinguished Encoding Rules (via PrivateKeyInfo from PKCS8)
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM = Privacy-Enhanced Mail (via PrivateKeyInfo from PKCS8)
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}