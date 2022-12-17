package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor {
    public interface Provider<P> : Cipher.Provider<P>, AeadEncryptor.Provider<P> {
        public override val defaultParameters: P
        public override fun syncCipher(parameters: P): AeadSyncCipher
    }
}

public interface AeadSyncCipher : AeadCipher, SyncCipher, SyncAeadEncryptor, SyncAeadDecryptor
public interface AeadAsyncCipher : AeadCipher, AsyncCipher, AsyncAeadEncryptor, AsyncAeadDecryptor

public fun <P : CopyableCryptographyParameters<P, B>, B> AeadCipher.Provider<P>.syncCipher(
    block: B.() -> Unit,
): AeadSyncCipher = syncCipher(defaultParameters.copy(block))
