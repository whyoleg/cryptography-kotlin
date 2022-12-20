package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*

public typealias HashAlgorithmIdentifier = CryptographyAlgorithmIdentifier<HashAlgorithm>

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
public class HashAlgorithm(
    hasherProvider: HasherProvider<CryptographyParameters.Empty>,
    operationId: CryptographyOperationId,
) : CryptographyAlgorithm {
    public val hasher: HasherFactory<CryptographyParameters.Empty> = hasherProvider.factory(
        operationId = operationId,
        defaultParameters = CryptographyParameters.Empty,
    )
}
