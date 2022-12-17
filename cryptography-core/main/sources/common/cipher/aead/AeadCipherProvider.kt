package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public interface AeadCipherProvider<P> : CipherProvider<P>, AeadEncryptorProvider<P>, AeadDecryptorProvider<P> {
    public override fun syncCipher(parameters: P): AeadSyncCipher
    public override fun asyncCipher(parameters: P): AeadAsyncCipher
}

public fun <P : CopyableCryptographyParameters<P, B>, B> AeadCipherProvider<P>.syncCipher(
    block: B.() -> Unit,
): AeadSyncCipher = syncCipher(defaultCipherParameters.copy(block))
