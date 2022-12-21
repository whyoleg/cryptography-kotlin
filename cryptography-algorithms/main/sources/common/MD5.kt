package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public fun MD5(hasherProvider: HasherProvider<CryptographyParameters.Empty>): HashAlgorithm = HashAlgorithm(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("MD5"),
)

public object MD5 : CryptographyAlgorithmIdentifier<HashAlgorithm>
