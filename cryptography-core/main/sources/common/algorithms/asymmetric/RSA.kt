package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface RSA<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {
    public fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<PublicKey.Format, PublicK>
    public fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<PrivateKey.Format, PrivateK>

    public fun keyPairGenerator(
        keySize: BinarySize = 2048.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
        publicExponent: PublicExponent = PublicExponent.F4,
    ): KeyGenerator<KP>

    //TODO: replace with some kind of MPP BigInt
    public sealed class PublicExponent {
        public object F4 : PublicExponent()
        public class Number internal constructor(public val value: Long) : PublicExponent()
        public class Bytes internal constructor(public val value: ByteArray) : PublicExponent()
        public class Text internal constructor(public val value: String) : PublicExponent()

        public companion object {
            public operator fun invoke(value: Int): PublicExponent = Number(value.toLong())
            public operator fun invoke(value: Long): PublicExponent = Number(value)
            public operator fun invoke(value: ByteArray): PublicExponent = Bytes(value)
            public operator fun invoke(value: String): PublicExponent = Text(value)
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

    @SubclassOptInRequired(ProviderApi::class)
    public interface OAEP : RSA<OAEP.PublicKey, OAEP.PrivateKey, OAEP.KeyPair> {
        public companion object : CryptographyAlgorithmId<OAEP>()

        @SubclassOptInRequired(ProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(ProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            public fun encryptor(): AuthenticatedEncryptor
        }

        @SubclassOptInRequired(ProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            public fun decryptor(): AuthenticatedDecryptor
        }
    }

    @SubclassOptInRequired(ProviderApi::class)
    public interface PSS : RSA<PSS.PublicKey, PSS.PrivateKey, PSS.KeyPair> {
        public companion object : CryptographyAlgorithmId<PSS>()

        @SubclassOptInRequired(ProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(ProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            public fun signatureVerifier(saltLength: BinarySize): SignatureVerifier
        }

        @SubclassOptInRequired(ProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            public fun signatureGenerator(saltLength: BinarySize): SignatureGenerator
        }
    }
}
