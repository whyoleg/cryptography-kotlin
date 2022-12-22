package dev.whyoleg.cryptography.algorithms.symmetric.mac

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.engine.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*

//TODO: decide on how we can support CMAC/GMAC

public class HMAC(
    keyGeneratorProvider: KeyGeneratorProvider<KeyGeneratorParameters, Key>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyOperationParameters.Empty, Key, Key.Format>,
) : CryptographyAlgorithm {
    public companion object : CryptographyAlgorithmIdentifier<HMAC>

    public val keyGenerator: KeyGeneratorFactory<KeyGeneratorParameters, Key> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = KeyGeneratorParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyOperationParameters.Empty, Key, Key.Format> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = CryptographyOperationParameters.Empty,
    )

    public class Key(
        signatureProvider: SignatureProvider<CryptographyOperationParameters.Empty>,
        keyEncoderProvider: KeyEncoderProvider<CryptographyOperationParameters.Empty, Format>,
    ) {
        public val signature: SignatureFactory<CryptographyOperationParameters.Empty> = signatureProvider.factory(
            operationId = CryptographyOperationId("HMAC-SHA"), //TODO: Sha
            defaultParameters = CryptographyOperationParameters.Empty,
        )
        public val encoder: KeyEncoderFactory<CryptographyOperationParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("HMAC"),
            defaultParameters = CryptographyOperationParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class KeyGeneratorParameters(
        public val digest: CryptographyAlgorithmIdentifier<Digest> = SHA512,
    ) : CryptographyOperationParameters {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }
}
