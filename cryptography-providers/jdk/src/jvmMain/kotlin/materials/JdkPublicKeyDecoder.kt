package dev.whyoleg.cryptography.jdk.materials


import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import java.security.spec.*

internal abstract class JdkPublicKeyDecoder<KF : KeyFormat, K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
    private val pemAlgorithm: String = algorithm,
) : KeyDecoder<KF, K> {
    protected val keyFactory = state.keyFactory(algorithm)

    private fun decode(input: ByteArray): JPublicKey = keyFactory.use { it.generatePublic(X509EncodedKeySpec(input)) }

    protected abstract fun JPublicKey.convert(): K

    override fun decodeFromBlocking(format: KF, input: ByteArray): K = when (format.name) {
        "DER" -> decode(input)
        "PEM" -> decode(input.decodeFromPem("PUBLIC KEY"))
        else  -> error("$format is not  supported")
    }.convert()
}
