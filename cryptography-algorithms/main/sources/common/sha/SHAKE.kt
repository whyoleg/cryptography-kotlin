package dev.whyoleg.cryptography.algorithms.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.hash.*

public abstract class SHAKE : HashProvider<SHAKE.Parameters> {
    public object B128 : CryptographyAlgorithm<SHAKE>
    public object B256 : CryptographyAlgorithm<SHAKE>

    final override val defaultHashParameters: Parameters get() = Parameters.Default

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
