package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.operations.*

public class SymmetricKeyParameters(
    public val size: SymmetricKeySize,
) : CryptographyOperationParameters.Copyable<SymmetricKeyParameters, SymmetricKeyParameters.Builder>() {
    override fun createBuilder(): Builder = Builder(size)
    override fun buildFrom(builder: Builder): SymmetricKeyParameters = SymmetricKeyParameters(builder.size)
    public class Builder internal constructor(
        public var size: SymmetricKeySize,
    )

    public companion object {
        public val Default: SymmetricKeyParameters = SymmetricKeyParameters(SymmetricKeySize.B256)
    }
}
