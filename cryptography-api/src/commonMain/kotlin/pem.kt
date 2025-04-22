/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import kotlinx.io.bytestring.*

public interface PemEncodable {
    public fun encodeToPemString(): String
    public fun encodeToPemByteString(): ByteString
}

public interface PemDecodable<T> {
    public fun decodeFromPem(text: String): T
    public fun decodeFromPem(bytes: ByteString): T
}
