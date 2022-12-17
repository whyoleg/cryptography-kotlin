package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyGeneratorProvider<K, P : CryptographyParameters> {
    public val defaultKeyGeneratorParameters: P
    public fun syncKeyGenerator(parameters: P = defaultKeyGeneratorParameters): SyncKeyGenerator<K>
    public fun asyncKeyGenerator(parameters: P = defaultKeyGeneratorParameters): AsyncKeyGenerator<K>
}


public fun <K, P : CopyableCryptographyParameters<P, B>, B> KeyGeneratorProvider<K, P>.syncKeyGenerator(
    block: B.() -> Unit,
): SyncKeyGenerator<K> = syncKeyGenerator(defaultKeyGeneratorParameters.copy(block))
