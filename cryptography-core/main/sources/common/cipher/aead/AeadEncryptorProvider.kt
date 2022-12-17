package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.cipher.*

public interface AeadEncryptorProvider<P> : EncryptorProvider<P> {
    public override fun syncEncryptor(parameters: P): SyncAeadEncryptor
    public override fun asyncEncryptor(parameters: P): AsyncAeadEncryptor
    public override fun encryptFunction(parameters: P): AeadEncryptFunction
}
