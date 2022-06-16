package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*

public interface Cipher : CryptographyPrimitive, Encryptor, Decryptor {
    public interface Sync<B : CipherBox> : Cipher, Encryptor.Sync<B>, Decryptor.Sync<B>
    public interface Async<B : CipherBox> : Cipher, Encryptor.Async<B>, Decryptor.Async<B>
    public interface Stream : Cipher, Encryptor.Stream, Decryptor.Stream

    public interface WithContext<C> : Cipher, Encryptor.WithContext<C>, Decryptor.WithContext<C> {
        public interface Sync<C, B : CipherBox> :
            WithContext<C>,
            Encryptor.WithContext.Sync<C, B>,
            Decryptor.WithContext.Sync<C, B>

        public interface Async<C, B : CipherBox> :
            WithContext<C>,
            Encryptor.WithContext.Async<C, B>,
            Decryptor.WithContext.Async<C, B>

        public interface Stream<C> :
            WithContext<C>,
            Encryptor.WithContext.Stream<C>,
            Decryptor.WithContext.Stream<C>
    }
}
