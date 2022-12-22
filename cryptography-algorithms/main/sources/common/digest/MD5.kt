package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

@ProviderApi
public fun MD5(hasherProvider: HasherProvider<CryptographyOperationParameters.Empty>): Digest = Digest(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("MD5"),
)

@InsecureAlgorithm
public object MD5 : CryptographyAlgorithmIdentifier<Digest>()
