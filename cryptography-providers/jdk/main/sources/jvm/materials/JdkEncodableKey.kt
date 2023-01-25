package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal open class JdkEncodableKey<KF : KeyFormat>(
    private val key: JKey,
    private val pemAlgorithm: String = key.algorithm,
) : EncodableKey<KF> {

    override fun encodeToBlocking(format: KF): Buffer = when (format.name) {
        "RAW" -> {
            check(key.format == "RAW") { "Wrong JDK Key format, expected `RAW` got `${key.format}`" }
            key.encoded
        }
        "DER" -> {
            check(key.format == "PKCS#8" || key.format == "X.509") { "Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`" }
            key.encoded
        }
        "PEM" -> {
            val type = pemAlgorithm + when (key.format) {
                "PKCS#8" -> " PRIVATE KEY"
                "X.509"  -> " PUBLIC KEY"
                else     -> error("Wrong JDK Key format, expected `PKCS#8` or `X.509 got `${key.format}`")
            }
            key.encoded.encodeToPem(type)
        }
        else  -> error("$format is not supported")
    }
}
