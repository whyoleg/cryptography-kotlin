package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public sealed interface Decryptor : CryptographyPrimitive {
    public interface Sync<B : CipherBox> : Decryptor {
        public fun plaintextSize(ciphertextSize: BinarySize): BinarySize
        public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

        public fun decrypt(ciphertextInput: BufferView): BufferView
        public fun decrypt(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
        public fun decryptBoxed(ciphertextInput: B): BufferView
        public fun encryptBoxed(ciphertextInput: B, plaintextOutput: BufferView): BufferView
    }

    public interface Async<B : CipherBox> : Decryptor {
        public fun plaintextSize(ciphertextSize: BinarySize): BinarySize
        public fun plaintextBoxedSize(ciphertextSize: BinarySize): BinarySize

        public suspend fun decrypt(ciphertextInput: BufferView): BufferView
        public suspend fun decrypt(ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
        public suspend fun decryptBoxed(ciphertextInput: B): BufferView
        public suspend fun encryptBoxed(ciphertextInput: B, plaintextOutput: BufferView): BufferView
    }

    public interface Stream : Decryptor {
        public fun createDecryptFunction(): DecryptFunction
    }

    public interface WithContext<C> : Decryptor {
        public interface Sync<C, B : CipherBox> : WithContext<C> {
            public fun plaintextSize(context: C, ciphertextSize: BinarySize): BinarySize
            public fun plaintextBoxedSize(context: C, ciphertextSize: BinarySize): BinarySize

            public fun decrypt(context: C, ciphertextInput: BufferView): BufferView
            public fun decrypt(context: C, ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
            public fun decryptBoxed(context: C, ciphertextInput: B): BufferView
            public fun encryptBoxed(context: C, ciphertextInput: B, plaintextOutput: BufferView): BufferView
        }

        public interface Async<C, B : CipherBox> : WithContext<C> {
            public fun plaintextSize(context: C, ciphertextSize: BinarySize): BinarySize
            public fun plaintextBoxedSize(context: C, ciphertextSize: BinarySize): BinarySize

            public suspend fun decrypt(context: C, ciphertextInput: BufferView): BufferView
            public suspend fun decrypt(context: C, ciphertextInput: BufferView, plaintextOutput: BufferView): BufferView
            public suspend fun decryptBoxed(context: C, ciphertextInput: B): BufferView
            public suspend fun encryptBoxed(context: C, ciphertextInput: B, plaintextOutput: BufferView): BufferView
        }

        public interface Stream<C> : WithContext<C> {
            public fun createDecryptFunction(context: C): DecryptFunction
        }
    }
}
