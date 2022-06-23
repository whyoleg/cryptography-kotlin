package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.bignumber.*
import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*
import dev.whyoleg.vio.*

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
public sealed interface RsaParameters : CryptographyParameters {
    public val keySize: KeySize
    public val publicExponent: BigInt
}

public sealed interface RsaParametersBuilder<P : RsaParameters> : CryptographyParametersBuilder<P> {
    public fun keySize(value: KeySize)
    public fun publicExponent(value: BigInt)
}

public sealed interface RsaOaepParameters : RsaParameters {
    public val hash: HashParameters
}

public sealed interface RsaOaepParametersBuilder : RsaParametersBuilder<RsaOaepParameters> {
    public fun hash(value: HashParameters)
}

public object RsaOaepParametersFactory : CryptographyParametersFactory<RsaOaepParameters, RsaOaepParametersBuilder>(
    createBuilder = ::RsaOaepParametersImpl,
    build = { it as RsaOaepParameters }
)

private class RsaOaepParametersImpl : RsaOaepParameters, RsaOaepParametersBuilder {
    override var keySize: KeySize = KeySize(1024.bits) //TODO: default
    override var publicExponent: BigInt = BigInt(65537) //TODO: default
    override var hash: HashParameters = Sha.SHA256 //TODO: default

    override fun keySize(value: KeySize) {
        keySize = value
    }

    override fun publicExponent(value: BigInt) {
        publicExponent = value
    }

    override fun hash(value: HashParameters) {
        hash = value
    }
}
