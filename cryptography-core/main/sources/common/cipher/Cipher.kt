package dev.whyoleg.cryptography.cipher

public interface Cipher : Encryptor, Decryptor
public interface SyncCipher : Cipher, SyncEncryptor, SyncDecryptor
public interface AsyncCipher : Cipher, AsyncEncryptor, AsyncDecryptor
