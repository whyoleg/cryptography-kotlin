package dev.whyoleg.cryptography.algorithms.mac

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

//TODO: decide on how we can support CMAC/GMAC

public class HMAC(
    keyGeneratorProvider: KeyGeneratorProvider<KeyGeneratorParameters, Key>,
    keyDecoderProvider: KeyDecoderProvider<CryptographyParameters.Empty, Key>,
) : CryptographyAlgorithm {
    public companion object : CryptographyAlgorithmIdentifier<HMAC>

    public val keyGenerator: KeyGeneratorFactory<KeyGeneratorParameters, Key> = keyGeneratorProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = KeyGeneratorParameters.Default,
    )

    public val keyDecoder: KeyDecoderFactory<CryptographyParameters.Empty, Key> = keyDecoderProvider.factory(
        operationId = CryptographyOperationId("HMAC"),
        defaultParameters = CryptographyParameters.Empty,
    )

    public class Key(
        signatureProvider: SignatureProvider<CryptographyParameters.Empty>,
        keyEncoderProvider: KeyEncoderProvider<CryptographyParameters.Empty>,
    ) {
        public val signature: SignatureFactory<CryptographyParameters.Empty> = signatureProvider.factory(
            operationId = CryptographyOperationId("HMAC-SHA"), //TODO: Sha
            defaultParameters = CryptographyParameters.Empty,
        )
        public val encoder: KeyEncoderFactory<CryptographyParameters.Empty> = keyEncoderProvider.factory(
            operationId = CryptographyOperationId("HMAC"),
            defaultParameters = CryptographyParameters.Empty,
        )
    }

    public class KeyGeneratorParameters(
        public val hashAlgorithmIdentifier: HashAlgorithmIdentifier = SHA512,
    ) : CryptographyParameters {
        public companion object {
            public val Default: KeyGeneratorParameters = KeyGeneratorParameters()
        }
    }
}
