package dev.whyoleg.cryptography.jdk.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.materials.key.*
import javax.crypto.*

internal class JdkSecretEncodableKey<KF : KeyFormat>(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
) : EncodableKey<KF> {
    override fun encodeToBlocking(format: KF): Buffer {
        if (format is KeyFormat.RAW && key.format == "RAW") return key.encoded
        TODO("$format is not yet supported")
    }

    override fun encodeToBlocking(format: KF, output: Buffer): Buffer = encodeToBlocking(format).copyInto(output)

    override suspend fun encodeTo(format: KF): Buffer {
        return state.execute { encodeToBlocking(format) }
    }

    override suspend fun encodeTo(format: KF, output: Buffer): Buffer {
        return state.execute { encodeToBlocking(format, output) }
    }
}

