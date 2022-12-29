package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmId<*>,
) : CryptographyException("Algorithm not found: $algorithm")
