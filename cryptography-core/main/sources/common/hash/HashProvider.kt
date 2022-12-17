package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*

public interface HashProvider<P : CryptographyParameters> {
    public val defaultHashParameters: P
    public fun syncHasher(parameters: P = defaultHashParameters): SyncHasher
    public fun asyncHasher(parameters: P = defaultHashParameters): AsyncHasher
    public fun hashFunction(parameters: P = defaultHashParameters): HashFunction
}

public fun <P : CopyableCryptographyParameters<P, B>, B> HashProvider<P>.syncHasher(
    block: B.() -> Unit,
): SyncHasher = syncHasher(defaultHashParameters.copy(block))
