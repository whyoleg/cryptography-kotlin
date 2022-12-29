package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
@SubclassOptInRequired(ProviderApi::class)
public abstract class Digest : CryptographyAlgorithm, Hasher
