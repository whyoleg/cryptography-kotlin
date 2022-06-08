package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*

public interface RsaOaep :
    KeyPair,
    KeyEncodePrimitive<KeyPairFormat> {
    public val public: Public
    public val private: Private

    public interface Public :
        PublicKey,
        EncryptPrimitive<Unit>,
        KeyEncodePrimitive<PublicKeyFormat> {
        public companion object :
            PrimitiveDecodeParametersProvider<Public, PublicKeyFormat, RsaOaepParameters, RsaOaepParametersBuilder> {
            override val decodeFactory: RsaOaepParametersFactory get() = RsaOaepParametersFactory
        }
    }

    public interface Private :
        PrivateKey,
        DecryptPrimitive<Unit>,
        KeyEncodePrimitive<PrivateKeyFormat> {
        public companion object :
            PrimitiveDecodeParametersProvider<Private, PrivateKeyFormat, RsaOaepParameters, RsaOaepParametersBuilder> {
            override val decodeFactory: RsaOaepParametersFactory get() = RsaOaepParametersFactory
        }
    }

    public companion object :
        PrimitiveDecodeParametersProvider<RsaOaep, KeyPairFormat, RsaOaepParameters, RsaOaepParametersBuilder>,
        PrimitiveGenerateParametersProvider<RsaOaep, RsaOaepParameters, RsaOaepParametersBuilder> {
        override val decodeFactory: RsaOaepParametersFactory get() = RsaOaepParametersFactory
        override val generateFactory: RsaOaepParametersFactory get() = RsaOaepParametersFactory
    }
}