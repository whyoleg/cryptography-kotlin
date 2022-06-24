package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.jvm.*

public abstract class CipherBox(public val ciphertext: Ciphertext)

@JvmInline
public value class Ciphertext(public val value: BufferView)

@JvmInline
public value class Plaintext(public val value: BufferView)

@JvmInline
public value class AuthTag(public val value: BufferView)

@JvmInline
public value class AssociatedData(public val value: BufferView)

@JvmInline
public value class InitializationVector(public val value: BufferView)

@JvmInline
public value class Nonce(public val value: BufferView)

public interface BaseCipher : BaseEncryptor, BaseDecryptor
public interface SyncCipher : BaseCipher, SyncEncryptor, SyncDecryptor
public interface AsyncCipher : BaseCipher, AsyncEncryptor, AsyncDecryptor
public interface StreamCipher : BaseCipher, StreamEncryptor, StreamDecryptor

public interface BaseBoxedCipher<B : CipherBox> : BaseBoxedEncryptor<B>, BaseBoxedDecryptor<B>
public interface SyncBoxedCipher<B : CipherBox> : BaseBoxedCipher<B>, SyncBoxedEncryptor<B>, SyncBoxedDecryptor<B>
public interface AsyncBoxedCipher<B : CipherBox> : BaseBoxedCipher<B>, AsyncBoxedEncryptor<B>, AsyncBoxedDecryptor<B>
