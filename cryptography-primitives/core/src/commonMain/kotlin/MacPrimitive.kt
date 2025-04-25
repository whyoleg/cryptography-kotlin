/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface MacPrimitive<P> {
    public fun createMacFunction(parameters: P): MacFunction<P>

    public fun computeMac(data: ByteString, parameters: P): ByteString
    public fun computeMac(data: RawSource, parameters: P): ByteString

    public fun verifyMac(data: ByteString, mac: ByteString, parameters: P)
    public fun verifyMac(data: RawSource, mac: ByteString, parameters: P)

    public fun tryVerifyMac(data: ByteString, mac: ByteString, parameters: P): Boolean
    public fun tryVerifyMac(data: RawSource, mac: ByteString, parameters: P): Boolean
}

public interface MacFunction<P> : AccumulatingFunction<P> {
    public fun computeMac(): ByteString
    public fun verifyMac(mac: ByteString)
    public fun tryVerifyMac(mac: ByteString): Boolean
}
