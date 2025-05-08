/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface HashPrimitive {
    public val outputSize: Int

    public fun createHashFunction(): HashFunction

    public fun hash(data: ByteString): ByteString
    public fun hash(data: RawSource): ByteString
}

public interface HashFunction : AccumulatingFunction {
    public fun hash(): ByteString
}

public interface ExtendableHashPrimitive : HashPrimitive {
    public override fun createHashFunction(): ExtendableHashFunction

    public fun hash(data: ByteString, outputSize: Int): ByteString
    public fun hash(data: RawSource, outputSize: Int): ByteString
}

public interface ExtendableHashFunction : HashFunction {
    public fun hash(outputSize: Int): ByteString
}
