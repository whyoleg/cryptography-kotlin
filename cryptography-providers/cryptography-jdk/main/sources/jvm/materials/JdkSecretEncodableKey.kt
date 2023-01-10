package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal class JdkSecretEncodableKey<KF : KeyFormat>(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : EncodableKey<KF> {
    override fun encodeToBlocking(format: KF): Buffer {
        if (format is KeyFormat.RAW && key.format == "RAW") return key.encoded
        TODO("$format is not yet supported")
    }

    override suspend fun encodeTo(format: KF): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

