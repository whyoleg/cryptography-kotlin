/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.async

import kotlinx.io.bytestring.*

// TODO: add boxed

public interface EncryptPrimitive<P> {
    public suspend fun encrypt(plaintext: ByteString, parameters: P): ByteString
}

public interface DecryptPrimitive<P> {
    public suspend fun decrypt(ciphertext: ByteString, parameters: P): ByteString
}
