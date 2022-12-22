@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
public class Digest @ProviderApi constructor(
    hasherProvider: HasherProvider<CryptographyOperationParameters.Empty>,
    operationId: CryptographyOperationId,
) : CryptographyAlgorithm() {
    public val hasher: HasherFactory<CryptographyOperationParameters.Empty> = hasherProvider.factory(
        operationId = operationId,
        defaultParameters = CryptographyOperationParameters.Empty,
    )
}
