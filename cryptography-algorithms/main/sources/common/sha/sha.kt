package dev.whyoleg.cryptography.algorithms.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public sealed class SHA3 : HashAlgorithm {
    public object B224 : SHA3() //etc
    public object B512 : SHA3() //etc
}

public class SHAKE128(
    public val digestSize: BinarySize = 128.bytes,
) : HashAlgorithm
