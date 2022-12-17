package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface CipherProvider<P> : EncryptorProvider<P>, DecryptorProvider<P> {
    public val defaultCipherParameters: P
    override val defaultEncryptParameters: P get() = defaultCipherParameters
    override val defaultDecryptParameters: P get() = defaultCipherParameters

    public fun syncCipher(parameters: P = defaultCipherParameters): SyncCipher
    public fun asyncCipher(parameters: P = defaultCipherParameters): AsyncCipher

    override fun syncEncryptor(parameters: P): SyncEncryptor = syncCipher(parameters)
    override fun asyncEncryptor(parameters: P): AsyncEncryptor = asyncEncryptor(parameters)
    override fun syncDecryptor(parameters: P): SyncDecryptor = syncCipher(parameters)
    override fun asyncDecryptor(parameters: P): AsyncDecryptor = asyncCipher(parameters)
}

public fun <P : CopyableCryptographyParameters<P, B>, B> CipherProvider<P>.syncCipher(
    block: B.() -> Unit,
): SyncCipher = syncCipher(defaultCipherParameters.copy(block))
