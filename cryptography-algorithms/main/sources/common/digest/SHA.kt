package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

@ProviderApi
public fun SHA(hasherProvider: HasherProvider<CryptographyOperationParameters.Empty>): Digest = Digest(
    hasherProvider = hasherProvider,
    operationId = CryptographyOperationId("SHA"),
)

@InsecureAlgorithm
public object SHA1 : CryptographyAlgorithmIdentifier<Digest>()
public object SHA256 : CryptographyAlgorithmIdentifier<Digest>()
public object SHA512 : CryptographyAlgorithmIdentifier<Digest>()

public object SHA3 {
    public object B224 : CryptographyAlgorithmIdentifier<Digest>()
    public object B512 : CryptographyAlgorithmIdentifier<Digest>()
}

private fun test(engine: CryptographyProvider) {
    val shake = engine.get(SHAKE.B128)

    val hasher = shake.hasher {
        digestSize = 256.bytes
    }

    hasher.hashBlocking(ByteArray(10))
}
