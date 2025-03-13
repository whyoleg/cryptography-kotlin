/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface CipherPrimitive<P> : EncryptPrimitive<P>, DecryptPrimitive<P>

public interface BoxCipherPrimitive<P, SB : CipherBox> :
    CipherPrimitive<P>,
    BoxEncryptPrimitive<P, SB>,
    BoxDecryptPrimitive<P, SB>

public interface StreamingCipherPrimitive<P> :
    CipherPrimitive<P>,
    StreamingEncryptPrimitive<P>,
    StreamingDecryptPrimitive<P>

public interface EncryptPrimitive<P> {
    public fun encrypt(plaintext: ByteString, parameters: P): ByteString
}

public interface BoxEncryptPrimitive<P, SB : CipherBox> : EncryptPrimitive<P> {
    public fun encryptToBox(plaintext: ByteString): SB // TODO: recheck if that's always true
    public fun encryptToBox(plaintext: ByteString, parameters: P): SB
}

public interface StreamingEncryptPrimitive<P> : EncryptPrimitive<P> {
    public fun encryptingSource(plaintext: RawSource, parameters: P): RawSource
    public fun encryptingSink(ciphertext: RawSink, parameters: P): RawSink
}

public interface DecryptPrimitive<P> {
    public fun decrypt(ciphertext: ByteString, parameters: P): ByteString
}

public interface BoxDecryptPrimitive<P, SB : CipherBox> : DecryptPrimitive<P> {
    public fun decryptFromBox(cipherbox: SB): ByteString
}

public interface StreamingDecryptPrimitive<P> : DecryptPrimitive<P> {
    public fun decryptingSource(ciphertext: RawSource, parameters: P): RawSource
    public fun decryptingSink(plaintext: RawSink, parameters: P): RawSink
}
