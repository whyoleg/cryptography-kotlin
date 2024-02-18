/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*

internal abstract class JdkEncodableKey<KF : KeyFormat>(
    private val key: JKey,
    private val pemAlgorithm: String = key.algorithm,
) : EncodableKey<KF> {

    protected fun encodeToRaw(): ByteArray {
        check(key.format == "RAW") { "Wrong JDK Key format, expected `RAW` got `${key.format}`" }
        return key.encoded
    }

    protected fun encodeToDer(): ByteArray {
        check(key.format == "PKCS#8" || key.format == "X.509") { "Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`" }
        return key.encoded
    }
}
