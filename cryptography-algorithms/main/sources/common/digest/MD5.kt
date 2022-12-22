package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.engine.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*

public fun MD5(hasherProvider: HasherProvider<CryptographyOperationParameters.Empty>): Digest = Digest(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("MD5"),
)

public object MD5 : CryptographyAlgorithmIdentifier<Digest>
