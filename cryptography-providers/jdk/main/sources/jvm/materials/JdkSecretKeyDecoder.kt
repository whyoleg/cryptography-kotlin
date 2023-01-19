package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import javax.crypto.spec.*

internal class JdkSecretKeyDecoder<KF : KeyFormat, K : Key>(
    private val algorithm: String,
    private val keyWrapper: (JSecretKey) -> K,
) : KeyDecoder<KF, K> {
    override fun decodeFromBlocking(format: KF, input: Buffer): K = when (format) {
        is KeyFormat.RAW -> keyWrapper(SecretKeySpec(input, algorithm))
        else             -> error("$format is not yet supported")
    }
}
