@file:OptIn(ProviderApi::class)

package dev.whyoleg.cryptography.algorithms.random

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.random.*
import dev.whyoleg.cryptography.provider.*

public class PlatformDependantRandom @ProviderApi constructor(
    randomizerProvider: RandomizerProvider<CryptographyOperationParameters.Empty>,
) : CryptographyAlgorithm() {
    public companion object : CryptographyAlgorithmIdentifier<PlatformDependantRandom>()

    public val randomizer: RandomizerFactory<CryptographyOperationParameters.Empty> = randomizerProvider.factory(
        operationId = CryptographyOperationId("PlatformDependant"),
        defaultParameters = CryptographyOperationParameters.Empty,
    )
}
