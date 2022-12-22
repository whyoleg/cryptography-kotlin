package dev.whyoleg.cryptography.provider

import dev.whyoleg.cryptography.*

public class CryptographyAlgorithmNotFoundException(
    algorithm: CryptographyAlgorithmIdentifier<*>,
) : CryptographyException("Algorithm not found: $algorithm")
