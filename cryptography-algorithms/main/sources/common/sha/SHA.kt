package dev.whyoleg.cryptography.algorithms.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.hash.*

public abstract class SHA : HashProvider<CryptographyParameters.Empty> {
    override val defaultHashParameters: CryptographyParameters.Empty get() = CryptographyParameters.Empty
}

public object SHA1 : CryptographyAlgorithm<SHA>
public object SHA2 : CryptographyAlgorithm<SHA>
public object SHA512 : CryptographyAlgorithm<SHA>

public object SHA3 {
    public object B224 : CryptographyAlgorithm<SHA>
    public object B512 : CryptographyAlgorithm<SHA>
}

private fun test(engine: CryptographyEngine) {
    val shake = engine.get(SHAKE.B128)

    val hasher = shake.syncHasher {
        digestSize = 256.bytes
    }

    hasher.hash(ByteArray(10))
}
