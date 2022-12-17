package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface CipherProvider<P> : EncryptorProvider<P> {
    public val defaultCipherParameters: P
    override val defaultEncryptorParameters: P get() = defaultCipherParameters

    public fun syncCipher(parameters: P = defaultCipherParameters): SyncCipher
}

public fun <P : CopyableCryptographyParameters<P, B>, B> CipherProvider<P>.syncCipher(
    block: B.() -> Unit,
): SyncCipher = syncCipher(defaultCipherParameters.copy(block))
