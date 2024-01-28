/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.serialization.pem.*

internal open class JdkEncodableKey<KF : KeyFormat>(
    private val key: JKey,
    private val pemAlgorithm: String = key.algorithm,
) : EncodableKey<KF> {

    override fun encodeToBlocking(format: KF): ByteArray = when (format.name) {
        "RAW" -> {
            check(key.format == "RAW") { "Wrong JDK Key format, expected `RAW` got `${key.format}`" }
            key.encoded
        }
        "DER" -> {
            check(key.format == "PKCS#8" || key.format == "X.509") { "Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`" }
            key.encoded
        }
        "PEM" -> {
            val label = when (key.format) {
                "PKCS#8" -> PemLabel.PrivateKey
                "X.509"  -> PemLabel.PublicKey
                else     -> error("Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`")
            }
            PEM.encodeToByteArray(PemContent(label, key.encoded))
        }
        else  -> error("$format is not supported")
    }
}
