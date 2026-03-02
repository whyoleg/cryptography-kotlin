/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.jdk.*

internal abstract class JdkEncodableKey<F : EncodingFormat>(
    private val key: JKey,
) : Encodable<F> {
    protected fun encodeToDer(): ByteArray {
        check(key.format == "PKCS#8" || key.format == "X.509") { "Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`" }
        return key.encoded
    }
}
