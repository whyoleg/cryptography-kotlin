package dev.whyoleg.cryptography.cipher

public interface Cipher<C> : Encryptor<C>, Decryptor<C>

public interface BoxCipher<C, B : CipherBox> : Cipher<C>, BoxEncryptor<C, B>, BoxDecryptor<C, B>

//TODO: add cmac and gmac
