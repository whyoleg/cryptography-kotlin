/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface MacPrimitive : SignPrimitive, VerifyPrimitive

public interface SignPrimitive {
    public fun createSignFunction(): SignFunction

    public fun sign(data: ByteString): ByteString
    public fun sign(data: RawSource): ByteString
}

public interface VerifyPrimitive {
    public fun createVerifyFunction(): VerifyFunction

    public fun verify(data: ByteString, signature: ByteString)
    public fun verify(data: RawSource, signature: ByteString)

    public fun tryVerify(data: ByteString, signature: ByteString): Boolean
    public fun tryVerify(data: RawSource, signature: ByteString): Boolean
}

public interface SignFunction : AccumulatingFunction {
    public fun sign(): ByteString
}

public interface VerifyFunction : AccumulatingFunction {
    public fun verify(signature: ByteString)
    public fun tryVerify(signature: ByteString): Boolean
}
