package dev.whyoleg.cryptography.algorithms.sha

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.hash.*

public fun SHA(hasherProvider: HasherProvider<CryptographyParameters.Empty>): HashAlgorithm = HashAlgorithm(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("SHA"),
)

public object SHA1 : CryptographyAlgorithmIdentifier<HashAlgorithm>
public object SHA256 : CryptographyAlgorithmIdentifier<HashAlgorithm>
public object SHA512 : CryptographyAlgorithmIdentifier<HashAlgorithm>

public object SHA3 {
    public object B224 : CryptographyAlgorithmIdentifier<HashAlgorithm>
    public object B512 : CryptographyAlgorithmIdentifier<HashAlgorithm>
}

private fun test(engine: CryptographyEngine) {
    val shake = engine.get(SHAKE.B128)

    val hasher = shake.hasher {
        digestSize = 256.bytes
    }

    hasher.hashBlocking(ByteArray(10))
}
