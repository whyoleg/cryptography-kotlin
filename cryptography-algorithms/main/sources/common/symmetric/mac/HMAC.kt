package dev.whyoleg.cryptography.algorithms.symmetric.mac

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

//TODO: decide on how we can support CMAC/GMAC

public class HMAC(
    keyGeneratorProvider: KeyGeneratorProvider<KeyGeneratorParameters, Key>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key, Key.Format>,
) : CryptographyAlgorithm {
    public companion object : CryptographyAlgorithmIdentifier<HMAC>

    public val keyGenerator: KeyGeneratorFactory<KeyGeneratorParameters, Key> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = KeyGeneratorParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyParameters.Empty, Key, Key.Format> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = CryptographyParameters.Empty,
    )

    public class Key(
        signatureProvider: SignatureProvider<CryptographyParameters.Empty>,
        keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty, Format>,
    ) {
        public val signature: SignatureFactory<CryptographyParameters.Empty> = signatureProvider.factory(
            operationId = CryptographyOperationId("HMAC-SHA"), //TODO: Sha
            defaultParameters = CryptographyParameters.Empty,
        )
        public val encoder: KeyEncoderFactory<CryptographyParameters.Empty, Format> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("HMAC"),
            defaultParameters = CryptographyParameters.Empty,
        )

        public sealed class Format : KeyFormat {
            public object RAW : Format(), KeyFormat.RAW
            public object JWK : Format(), KeyFormat.JWK
        }
    }

    public class KeyGeneratorParameters(
        public val digest: CryptographyAlgorithmIdentifier<Digest> = SHA512,
    ) : CryptographyParameters {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }
}
