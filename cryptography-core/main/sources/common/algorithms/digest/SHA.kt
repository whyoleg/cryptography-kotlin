package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.provider.*

@InsecureAlgorithm
public object SHA1 : CryptographyAlgorithmId<Digest>()
public object SHA256 : CryptographyAlgorithmId<Digest>()
public object SHA384 : CryptographyAlgorithmId<Digest>()
public object SHA512 : CryptographyAlgorithmId<Digest>()

public object SHA3 {
    public object B224 : CryptographyAlgorithmId<Digest>()
    public object B512 : CryptographyAlgorithmId<Digest>()
}

private fun test(engine: CryptographyProvider) {
    engine.get(SHA256)

    val shake = engine.get(SHAKE.B128)

    val hasher = shake.hasher(256.bytes)

    hasher.hashBlocking(ByteArray(10))
}
