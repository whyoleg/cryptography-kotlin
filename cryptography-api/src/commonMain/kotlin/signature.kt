/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface TypedSignature

public interface SignPrimitive<P> : CryptographyPrimitive {
    public fun sign(data: ByteString, parameters: P): ByteString
    public fun sign(data: RawSource, parameters: P): ByteString
}

public interface VerifyPrimitive<P> : CryptographyPrimitive


public interface TypedSignPrimitive<P, R> : CryptographyPrimitive {
    public fun signTyped(data: ByteString, parameters: P): R
    public fun signTyped(data: RawSource, parameters: P): R
}

public class EcdsaSignature {
    public val r: ByteString get() = TODO()
    public val s: ByteString get() = TODO()

    public fun encodeToRaw(): ByteString = TODO()
    public fun encodeToDer(): ByteString = TODO()

    public companion object {
        public fun decodeFromRaw(bytes: ByteString): EcdsaSignature = TODO()
        public fun decodeFromDer(bytes: ByteString): EcdsaSignature = TODO()
    }
}
