package dev.whyoleg.cryptography.api

public interface Cipher : Encryptor, Decryptor
public interface SyncCipher : Cipher, SyncEncryptor, SyncDecryptor
public interface AeadSyncCipher : SyncCipher, AeadSyncEncryptor, AeadSyncDecryptor
public interface AsyncCipher : Cipher, AsyncEncryptor, AsyncDecryptor
public interface AeadAsyncCipher : AsyncCipher, AeadAsyncEncryptor, AeadAsyncDecryptor
