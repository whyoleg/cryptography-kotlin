package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*

public interface HashPrimitive : CryptographyPrimitive {
    public val hash: HashOperation
}
