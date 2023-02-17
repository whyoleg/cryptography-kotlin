package dev.whyoleg.cryptography.jdk.materials


import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import java.security.spec.*

internal abstract class JdkPrivateKeyDecoder<KF : KeyFormat, K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
    private val pemAlgorithm: String = algorithm,
) : KeyDecoder<KF, K> {
    private val keyFactory = state.keyFactory(algorithm)

    private fun decode(input: ByteArray): JPrivateKey = keyFactory.use { it.generatePrivate(PKCS8EncodedKeySpec(input)) }

    protected abstract fun JPrivateKey.convert(): K

    final override fun decodeFromBlocking(format: KF, input: ByteArray): K = when (format.name) {
        "DER" -> decode(input)
        "PEM" -> decode(input.decodeFromPem("PRIVATE KEY"))
        else  -> error("$format is not supported")
    }.convert()
}
