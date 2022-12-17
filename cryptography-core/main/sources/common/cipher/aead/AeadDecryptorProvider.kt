package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.cipher.*

public interface AeadDecryptorProvider<P> : DecryptorProvider<P> {
    public override fun syncDecryptor(parameters: P): SyncAeadDecryptor
    public override fun asyncDecryptor(parameters: P): AsyncAeadDecryptor
    public override fun decryptFunction(parameters: P): AeadDecryptFunction
}
