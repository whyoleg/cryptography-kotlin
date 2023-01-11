package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*

internal open class JdkEncodableKey<KF : KeyFormat>(
    private val state: JdkCryptographyState,
    private val key: JKey,
) : EncodableKey<KF> {
    override fun encodeToBlocking(format: KF): Buffer = when (format) {
        is KeyFormat.RAW -> {
            check(key.format == "RAW") { "Key format is not RAW" }
            key.encoded
        }
        is KeyFormat.DER -> {
            check(key.format == "PKCS#8" || key.format == "X.509") { "Key format is not DER" }
            key.encoded
        }
        else             -> TODO("$format is not yet supported")
    }

    override suspend fun encodeTo(format: KF): Buffer {
        return state.execute { encodeToBlocking(format) }
    }
}

