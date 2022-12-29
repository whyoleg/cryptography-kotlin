@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.symmetric.mac

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.provider.*

//TODO: decide on how we can support CMAC/GMAC

public class HMAC @ProviderApi constructor(
    keyGeneratorProvider: KeyGeneratorProvider<KeyGeneratorParameters, Key>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyOperationParameters.Empty, Key, Key.Format>,
) : CryptographyAlgorithm() {
    public companion object : CryptographyAlgorithmId<HMAC>()

    public val keyGenerator: KeyGeneratorFactory<KeyGeneratorParameters, Key> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = KeyGeneratorParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyOperationParameters.Empty, Key, Key.Format> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = CryptographyOperationParameters.Empty,
    )

    public class Key @ProviderApi constructor(
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
        public val digest: CryptographyAlgorithmId<Digest> = SHA512,
    ) : CryptographyOperationParameters() {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }
}
