package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import java.security.spec.*

internal abstract class JdkPublicKeyDecoder<KF : KeyFormat, K : Key>(
    protected val state: JdkCryptographyState,
    algorithm: String,
) : KeyDecoder<KF, K> {
    private val keyFactory = state.keyFactory(algorithm)

    protected abstract fun JPublicKey.convert(): K

    final override fun decodeFromBlocking(format: KF, input: Buffer): K = when (format) {
        is KeyFormat.DER -> keyFactory.use { it.generatePublic(X509EncodedKeySpec(input)) }.convert()
        is KeyFormat.PEM -> TODO("fix it")
        else             -> TODO()
    }

    final override suspend fun decodeFrom(format: KF, input: Buffer): K {
        return state.execute { decodeFromBlocking(format, input) }
    }
}
