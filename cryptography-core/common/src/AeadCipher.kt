package dev.whyoleg.cryptography

public interface BaseAeadCipher : BaseAeadEncryptor, BaseAeadDecryptor
public interface SyncAeadCipher : BaseAeadCipher, SyncAeadEncryptor, SyncAeadDecryptor
public interface AsyncAeadCipher : BaseAeadCipher, AsyncAeadEncryptor, AsyncAeadDecryptor
public interface StreamAeadCipher : BaseAeadCipher, StreamAeadEncryptor, StreamAeadDecryptor

public interface BaseBoxedAeadCipher<B : CipherBox> : BaseBoxedAeadEncryptor<B>, BaseBoxedAeadDecryptor<B>
public interface SyncBoxedAeadCipher<B : CipherBox> :
    BaseBoxedAeadCipher<B>,
    SyncBoxedAeadEncryptor<B>,
    SyncBoxedAeadDecryptor<B>

public interface AsyncBoxedAeadCipher<B : CipherBox> :
    BaseBoxedAeadCipher<B>,
    AsyncBoxedAeadEncryptor<B>,
    AsyncBoxedAeadDecryptor<B>
