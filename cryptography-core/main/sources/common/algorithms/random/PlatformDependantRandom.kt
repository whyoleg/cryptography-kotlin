package dev.whyoleg.cryptography.algorithms.random

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.random.*
import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(ProviderApi::class)
public interface PlatformDependantRandom : CryptographyAlgorithm, Randomizer {
    public companion object : CryptographyAlgorithmId<PlatformDependantRandom>()
}
