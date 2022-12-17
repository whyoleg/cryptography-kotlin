package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public class SymmetricKeyParameters(
    public val size: SymmetricKeySize,
) : CopyableCryptographyParameters<SymmetricKeyParameters, SymmetricKeyParameters.Builder>() {
    override fun builder(): Builder = Builder(size)
    override fun build(builder: Builder): SymmetricKeyParameters = SymmetricKeyParameters(builder.size)
    public class Builder internal constructor(
        public var size: SymmetricKeySize,
    )
}
