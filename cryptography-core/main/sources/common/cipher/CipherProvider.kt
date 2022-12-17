package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface CipherProvider<P> : EncryptorProvider<P>, DecryptorProvider<P> {
    public val defaultCipherParameters: P
    override val defaultEncryptParameters: P get() = defaultCipherParameters
    override val defaultDecryptParameters: P get() = defaultCipherParameters

    public fun syncCipher(parameters: P = defaultCipherParameters): SyncCipher
    public fun asyncCipher(parameters: P = defaultCipherParameters): AsyncCipher
}

public fun <P : CopyableCryptographyParameters<P, B>, B> CipherProvider<P>.syncCipher(
    block: B.() -> Unit,
): SyncCipher = syncCipher(defaultCipherParameters.copy(block))
