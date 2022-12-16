package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Cipher : Encryptor, Decryptor {
    public interface Provider<P> : Encryptor.Provider<P> {
        public override val defaultParameters: P
        public fun syncCipher(parameters: P = defaultParameters): SyncCipher
    }
}

public fun <P : CryptographyParameters<P, B>, B> Cipher.Provider<P>.syncCipher(
    block: B.() -> Unit,
): SyncCipher = syncCipher(defaultParameters.copy(block))

public interface SyncCipher : Cipher, SyncEncryptor, SyncDecryptor
public interface AsyncCipher : Cipher, AsyncEncryptor, AsyncDecryptor

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor {
    public interface Provider<P> : Cipher.Provider<P>, AeadEncryptor.Provider<P> {
        public override val defaultParameters: P
        public override fun syncCipher(parameters: P): AeadSyncCipher
    }
}

public interface AeadSyncCipher : AeadCipher, SyncCipher, SyncAeadEncryptor//, SyncAeadDecryptor
public interface AeadAsyncCipher : AsyncCipher, AeadAsyncEncryptor, AeadAsyncDecryptor
