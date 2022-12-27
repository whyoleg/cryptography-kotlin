@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

public abstract class RSA<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> @ProviderApi constructor(
    keyPairGeneratorProvider: KeyGeneratorProvider<KeyPairGeneratorParameters, KP>,
) : CryptographyAlgorithm() {

    public val keyPairGenerator: KeyGeneratorFactory<KeyPairGeneratorParameters, KP> = keyPairGeneratorProvider.factory(
        operationId = CryptographyOperationId("RSA"),
        defaultParameters = KeyPairGeneratorParameters.Default,
    )

    public class KeyPairGeneratorParameters(
        public val keySize: BinarySize = 2048.bits,
        public val publicExponent: PublicExponent = PublicExponent.F4,
        public val digest: CryptographyAlgorithmIdentifier<Digest> = SHA512,
    ) : CryptographyOperationParameters() {
        public companion object {
            public val Default: KeyPairGeneratorParameters = KeyPairGeneratorParameters()
        }
    }

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

    public abstract class KeyPair<PublicK : PublicKey, PrivateK : PrivateKey> @ProviderApi constructor(
        public val publicKey: PublicK,
        public val privateKey: PrivateK,
    )

    public abstract class PublicKey @ProviderApi constructor(
        keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
    ) {
        public val encoder: KeyEncoderFactory<CryptographyOperationParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("RSA"),
            defaultParameters = CryptographyOperationParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public abstract class PrivateKey @ProviderApi constructor(
        keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
    ) {
        public val encoder: KeyEncoderFactory<CryptographyOperationParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("RSA"),
            defaultParameters = CryptographyOperationParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object PEM : Format(), KeyFormat.PEM
            public object DER : Format(), KeyFormat.DER
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class OAEP @ProviderApi constructor(
        keyPairGeneratorProvider: KeyGeneratorProvider<KeyPairGeneratorParameters, KeyPair>,
    ) : RSA<OAEP.PublicKey, OAEP.PrivateKey, OAEP.KeyPair>(keyPairGeneratorProvider) {
        public companion object : CryptographyAlgorithmIdentifier<OAEP>()

        public class KeyPair @ProviderApi constructor(
            publicKey: PublicKey,
            privateKey: PrivateKey,
        ) : RSA.KeyPair<PublicKey, PrivateKey>(publicKey, privateKey)

        public class PublicKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            encryptorProvider: AeadEncryptorProvider<CryptographyOperationParameters.Empty>,
        ) : RSA.PublicKey(keyEncoderProvider) {
            public val encryptor: AeadEncryptorFactory<CryptographyOperationParameters.Empty> = encryptorProvider.factory(
                operationId = CryptographyOperationId("RSA-OAEP"),
                defaultParameters = CryptographyOperationParameters.Empty,
            )
        }

        public class PrivateKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            decryptorProvider: AeadDecryptorProvider<CryptographyOperationParameters.Empty>,
        ) : RSA.PrivateKey(keyEncoderProvider) {
            public val decryptor: AeadDecryptorFactory<CryptographyOperationParameters.Empty> = decryptorProvider.factory(
                operationId = CryptographyOperationId("RSA-OAEP"),
                defaultParameters = CryptographyOperationParameters.Empty,
            )
        }
    }

    //TODO: signature parameters (saltLength)
    public class PSS @ProviderApi constructor(
        keyPairGeneratorProvider: KeyGeneratorProvider<KeyPairGeneratorParameters, KeyPair>,
    ) : RSA<PSS.PublicKey, PSS.PrivateKey, PSS.KeyPair>(keyPairGeneratorProvider) {
        public companion object : CryptographyAlgorithmIdentifier<PSS>()

        public class KeyPair @ProviderApi constructor(
            publicKey: PublicKey,
            privateKey: PrivateKey,
        ) : RSA.KeyPair<PublicKey, PrivateKey>(publicKey, privateKey)

        public class PublicKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            signatureVerifierProvider: SignatureVerifierProvider<SignatureParameters>,
        ) : RSA.PublicKey(keyEncoderProvider) {
            public val verifier: SignatureVerifierFactory<SignatureParameters> = signatureVerifierProvider.factory(
                operationId = CryptographyOperationId("RSA-PSS"),
                defaultParameters = SignatureParameters.Default,
            )
        }

        public class PrivateKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            signatureGeneratorProvider: SignatureGeneratorProvider<SignatureParameters>,
        ) : RSA.PrivateKey(keyEncoderProvider) {
            public val signer: SignatureGeneratorFactory<SignatureParameters> = signatureGeneratorProvider.factory(
                operationId = CryptographyOperationId("RSA-PSS"),
                defaultParameters = SignatureParameters.Default,
            )
        }

        public class SignatureParameters(
            public val saltLength: BinarySize = 0.bytes,
        ) : CryptographyOperationParameters() {
            public companion object {
                public val Default: SignatureParameters = SignatureParameters()
            }
        }
    }
}
