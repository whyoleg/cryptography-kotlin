/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface SignPrimitive<P> {
    public fun createSignFunction(parameters: P): SignFunction<P>

    public fun sign(data: ByteString, parameters: P): ByteString
    public fun sign(data: RawSource, parameters: P): ByteString
}

public interface VerifyPrimitive<P> {
    public fun createVerifyFunction(parameters: P): VerifyFunction<P>

    public fun verify(data: ByteString, signature: ByteString, parameters: P)
    public fun verify(data: RawSource, signature: ByteString, parameters: P)

    public fun tryVerify(data: ByteString, signature: ByteString, parameters: P): Boolean
    public fun tryVerify(data: RawSource, signature: ByteString, parameters: P): Boolean
}

public interface SignFunction<P> : AccumulatingFunction<P> {
    public fun sign(): ByteString
}

public interface VerifyFunction<P> : AccumulatingFunction<P> {
    public fun verify(signature: ByteString)
    public fun tryVerify(signature: ByteString): Boolean
}
