package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.cipher.*

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor

public interface AeadSyncCipher : AeadCipher, SyncCipher, SyncAeadEncryptor, SyncAeadDecryptor
public interface AeadAsyncCipher : AeadCipher, AsyncCipher, AsyncAeadEncryptor, AsyncAeadDecryptor
