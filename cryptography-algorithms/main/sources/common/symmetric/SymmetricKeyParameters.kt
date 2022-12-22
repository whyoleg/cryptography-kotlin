package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.operations.*

public class SymmetricKeyParameters(
    public val size: SymmetricKeySize,
) : CopyableCryptographyParameters<SymmetricKeyParameters, SymmetricKeyParameters.Builder>() {
    override fun builder(): Builder = Builder(size)
    override fun build(builder: Builder): SymmetricKeyParameters = SymmetricKeyParameters(builder.size)
    public class Builder internal constructor(
        public var size: SymmetricKeySize,
    )

    public companion object {
        public val Default: SymmetricKeyParameters = SymmetricKeyParameters(SymmetricKeySize.B256)
    }
}
