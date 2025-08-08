/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.bytestring.*

@Suppress("DEPRECATION_ERROR")
@Deprecated("Migrate to `PemDocument`", level = DeprecationLevel.ERROR)
public typealias PEM = Pem

@Suppress("DEPRECATION_ERROR")
@Deprecated("Migrate to `PemDocument`", level = DeprecationLevel.ERROR)
public object Pem {
    public fun encodeToByteString(content: PemContent): ByteString = encode(content).encodeToByteString()
    public fun encodeToByteArray(content: PemContent): ByteArray = encode(content).encodeToByteArray()
    public fun encode(content: PemContent): String = PemDocument(content.label, content.byteString).encodeToString()

    public fun decode(byteString: ByteString): PemContent = decode(byteString.decodeToString())
    public fun decode(bytes: ByteArray): PemContent = decode(bytes.decodeToString())
    public fun decode(string: String): PemContent = PemDocument.decode(string).let { PemContent(it.label, it.content) }
}
