package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyGeneratorProvider<P : CryptographyParameters, K> {
    public val defaultKeyGeneratorParameters: P
    public fun syncKeyGenerator(parameters: P = defaultKeyGeneratorParameters): SyncKeyGenerator<K>
    public fun asyncKeyGenerator(parameters: P = defaultKeyGeneratorParameters): AsyncKeyGenerator<K>
}


public fun <P : CopyableCryptographyParameters<P, B>, B, K> KeyGeneratorProvider<P, K>.syncKeyGenerator(
    block: B.() -> Unit,
): SyncKeyGenerator<K> = syncKeyGenerator(defaultKeyGeneratorParameters.copy(block))
