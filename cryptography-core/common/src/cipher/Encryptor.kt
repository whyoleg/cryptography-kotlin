package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface Encryptor : CryptographyPrimitive {
    public interface Sync<B : CipherBox> : Encryptor {
        public fun ciphertextSize(plaintextSize: BinarySize): BinarySize
        public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

        public fun encrypt(plaintextInput: BufferView): BufferView
        public fun encrypt(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
        public fun encryptBoxed(plaintextInput: BufferView): B
        public fun encryptBoxed(plaintextInput: BufferView, ciphertextOutput: B): B
    }

    public interface Async<B : CipherBox> : Encryptor {
        public fun ciphertextSize(plaintextSize: BinarySize): BinarySize
        public fun ciphertextBoxedSize(plaintextSize: BinarySize): BinarySize

        public suspend fun encrypt(plaintextInput: BufferView): BufferView
        public suspend fun encrypt(plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
        public suspend fun encryptBoxed(plaintextInput: BufferView): B
        public suspend fun encryptBoxed(plaintextInput: BufferView, ciphertextOutput: B): B
    }

    public interface Stream : Encryptor {
        public fun createEncryptFunction(): EncryptFunction
    }

    public interface WithContext<C> : Encryptor {
        public interface Sync<C, B : CipherBox> : WithContext<C> {
            public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
            public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize

            public fun encrypt(context: C, plaintextInput: BufferView): BufferView
            public fun encrypt(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
            public fun encryptBoxed(context: C, plaintextInput: BufferView): B
            public fun encryptBoxed(context: C, plaintextInput: BufferView, ciphertextOutput: B): B
        }

        public interface Async<C, B : CipherBox> : WithContext<C> {
            public fun ciphertextSize(context: C, plaintextSize: BinarySize): BinarySize
            public fun ciphertextBoxedSize(context: C, plaintextSize: BinarySize): BinarySize

            public suspend fun encrypt(context: C, plaintextInput: BufferView): BufferView
            public suspend fun encrypt(context: C, plaintextInput: BufferView, ciphertextOutput: BufferView): BufferView
            public suspend fun encryptBoxed(context: C, plaintextInput: BufferView): B
            public suspend fun encryptBoxed(context: C, plaintextInput: BufferView, ciphertextOutput: B): B
        }

        public interface Stream<C> : WithContext<C> {
            public fun createEncryptFunction(context: C): EncryptFunction
        }
    }
}
