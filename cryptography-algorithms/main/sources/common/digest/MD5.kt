package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public fun MD5(hasherProvider: HasherProvider<CryptographyParameters.Empty>): Digest = Digest(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("MD5"),
)

public object MD5 : CryptographyAlgorithmIdentifier<Digest>
