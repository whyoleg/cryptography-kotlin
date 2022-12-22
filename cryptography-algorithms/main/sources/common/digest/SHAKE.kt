package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.hash.*

public class SHAKE(
    hasherProvider: HasherProvider<Parameters>,
) : CryptographyAlgorithm {
    public object B128 : CryptographyAlgorithmIdentifier<SHAKE>
    public object B256 : CryptographyAlgorithmIdentifier<SHAKE>

    public val hasher: HasherFactory<Parameters> = hasherProvider.factory(
        operationId = CryptographyOperationId("SHAKE"),
        defaultParameters = Parameters.Default,
    )

    public class Parameters(
        public val digestSize: BinarySize = 128.bytes,
    ) : CopyableCryptographyParameters<Parameters, Parameters.Builder>() {
        override fun builder(): Builder = Builder(digestSize)
        override fun build(builder: Builder): Parameters = Parameters(builder.digestSize)
        public class Builder internal constructor(
            public var digestSize: BinarySize,
        )

        public companion object {
            public val Default: Parameters = Parameters()
        }
    }
}
