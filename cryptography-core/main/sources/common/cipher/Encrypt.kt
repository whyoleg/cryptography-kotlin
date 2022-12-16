package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Encryptor {
    public fun ciphertextSize(plaintextSize: Int): Int

    public interface Provider<P> {
        public val defaultParameters: P

        public fun syncEncryptor(parameters: P = defaultParameters): SyncEncryptor
        public fun asyncEncryptor(parameters: P = defaultParameters): AsyncEncryptor
        public fun encryptFunction(parameters: P = defaultParameters): EncryptFunction
    }
}

public interface SyncEncryptor : Encryptor {
    public fun encrypt(plaintextInput: Buffer): Buffer
    public fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}

public interface AsyncEncryptor : Encryptor {
    public suspend fun encrypt(plaintextInput: Buffer): Buffer
    public suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer
}

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

public interface EncryptFunction : Closeable {
    public fun ciphertextPartSize(plaintextPartSize: Int): Int
    public fun encryptPart(plaintextPartInput: Buffer): Buffer
    public fun encryptPart(plaintextPartInput: Buffer, ciphertextPartOutput: Buffer): Buffer

    public fun ciphertextFinalPartSize(plaintextFinalPartSize: Int): Int
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer): Buffer
    public fun encryptFinalPart(plaintextFinalPartInput: Buffer, ciphertextFinalPartOutput: Buffer): Buffer
}

public interface AeadEncryptFunction : EncryptFunction {
    //TODO: naming?
    public fun putAssociatedData(associatedData: Buffer)
}

public interface BoxedEncryptor<B : Any> {
    public fun ciphertextSize(plaintextSize: Int): Int
    public fun encrypt(plaintextInput: Buffer): B
    public fun encrypt(plaintextInput: Buffer, boxOutput: B): B
}
