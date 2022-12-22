@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.asymmetric

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
        //modulusLength: Number
        //publicExponent: BigInt
        //hash
    ) : CryptographyOperationParameters() {
        public companion object {
            public val Default: KeyPairGeneratorParameters = KeyPairGeneratorParameters()
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
        public class KeyPair @ProviderApi constructor(
            publicKey: PublicKey,
            privateKey: PrivateKey,
        ) : RSA.KeyPair<PublicKey, PrivateKey>(publicKey, privateKey)

        public class PublicKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            verifierProvider: VerifierProvider<CryptographyOperationParameters.Empty>,
        ) : RSA.PublicKey(keyEncoderProvider) {
            public val verifier: VerifierFactory<CryptographyOperationParameters.Empty> = verifierProvider.factory(
                operationId = CryptographyOperationId("RSA-PSS"),
                defaultParameters = CryptographyOperationParameters.Empty,
            )
        }

        public class PrivateKey @ProviderApi constructor(
            keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
            signerProvider: SignerProvider<CryptographyOperationParameters.Empty>,
        ) : RSA.PrivateKey(keyEncoderProvider) {
            public val signer: SignerFactory<CryptographyOperationParameters.Empty> = signerProvider.factory(
                operationId = CryptographyOperationId("RSA-PSS"),
                defaultParameters = CryptographyOperationParameters.Empty,
            )
        }
    }
}
