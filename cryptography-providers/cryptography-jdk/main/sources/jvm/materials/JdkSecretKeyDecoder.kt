package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import javax.crypto.spec.*

internal class JdkSecretKeyDecoder<KF : KeyFormat, K : Key>(
    private val state: JdkCryptographyState,
    private val algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
) : KeyDecoder<KF, K> {
    override fun decodeFromBlocking(format: KF, input: Buffer): K {
        if (format is KeyFormat.RAW) return keyWrapper(SecretKeySpec(input, algorithm))
        TODO("$format is not yet supported")
    }

    override suspend fun decodeFrom(format: KF, input: Buffer): K {
        return state.execute { decodeFromBlocking(format, input) }
    }
}
