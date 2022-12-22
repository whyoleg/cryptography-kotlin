package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
public class Digest(
    hasherProvider: HasherProvider<CryptographyParameters.Empty>,
    operationId: CryptographyOperationId,
) : CryptographyAlgorithm {
    public val hasher: HasherFactory<CryptographyParameters.Empty> = hasherProvider.factory(
        operationId = operationId,
        defaultParameters = CryptographyParameters.Empty,
    )
}
