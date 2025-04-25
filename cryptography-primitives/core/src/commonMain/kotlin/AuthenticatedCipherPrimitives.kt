/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface AuthenticatedCipherPrimitive<P> : AuthenticatedEncryptPrimitive<P>, AuthenticatedDecryptPrimitive<P>

public interface AuthenticatedCipherBoxPrimitive<P, SB : CipherBox> :
    AuthenticatedCipherPrimitive<P>,
    AuthenticatedBoxEncryptPrimitive<P, SB>,
    AuthenticatedBoxDecryptPrimitive<P, SB>

public interface AuthenticatedStreamingCipherPrimitive<P> :
    AuthenticatedCipherPrimitive<P>,
    AuthenticatedStreamingEncryptPrimitive<P>,
    AuthenticatedStreamingDecryptPrimitive<P>

public interface AuthenticatedEncryptPrimitive<P> {
    public fun encrypt(plaintext: ByteString, associatedData: ByteString?, parameters: P): ByteString
}

public interface AuthenticatedBoxEncryptPrimitive<P, SB : CipherBox> : AuthenticatedEncryptPrimitive<P> {
    public fun encryptToBox(plaintext: ByteString, associatedData: ByteString?): SB // TODO: recheck if that's always true
    public fun encryptToBox(plaintext: ByteString, associatedData: ByteString?, parameters: P): SB
}

public interface AuthenticatedStreamingEncryptPrimitive<P> : AuthenticatedEncryptPrimitive<P> {
    public fun encryptingSource(plaintext: RawSource, associatedData: ByteString?, parameters: P): RawSource
    public fun encryptingSink(ciphertext: RawSink, associatedData: ByteString?, parameters: P): RawSink
}

public interface AuthenticatedDecryptPrimitive<P> {
    public fun decrypt(ciphertext: ByteString, associatedData: ByteString?, parameters: P): ByteString
}

public interface AuthenticatedBoxDecryptPrimitive<P, SB : CipherBox> : AuthenticatedDecryptPrimitive<P> {
    public fun decryptFromBox(cipherbox: SB, associatedData: ByteString?): ByteString
}

public interface AuthenticatedStreamingDecryptPrimitive<P> : AuthenticatedDecryptPrimitive<P> {
    public fun decryptingSource(ciphertext: RawSource, associatedData: ByteString?, parameters: P): RawSource
    public fun decryptingSink(plaintext: RawSink, associatedData: ByteString?, parameters: P): RawSink
}
