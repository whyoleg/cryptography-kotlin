package dev.whyoleg.cryptography.cipher.aead

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*

public interface AeadEncryptor : Encryptor {

    public interface Provider<P> : Encryptor.Provider<P> {
        public override val defaultParameters: P

        public override fun syncEncryptor(parameters: P): SyncAeadEncryptor
        public override fun asyncEncryptor(parameters: P): AsyncAeadEncryptor
        public override fun encryptFunction(parameters: P): AeadEncryptFunction
    }
}

public interface SyncAeadEncryptor : SyncEncryptor, AeadEncryptor {
    public fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    override fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = encrypt(null, plaintextInput, ciphertextOutput)
}

public interface AsyncAeadEncryptor : AsyncEncryptor, AeadEncryptor {
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer
    public suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
    override suspend fun encrypt(plaintextInput: Buffer): Buffer = encrypt(null, plaintextInput)
    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer = encrypt(null, plaintextInput, ciphertextOutput)
}
