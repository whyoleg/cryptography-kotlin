package dev.whyoleg.cryptography.engine

import dev.whyoleg.cryptography.*

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmIdentifier<*>,
) : CryptographyException("Algorithm not found: $algorithm")
