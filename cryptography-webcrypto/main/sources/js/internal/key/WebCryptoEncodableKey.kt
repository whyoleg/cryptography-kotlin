package dev.whyoleg.cryptography.webcrypto.internal.key

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.external.*
import dev.whyoleg.cryptography.webcrypto.internal.*

//TODO: abstract class?
internal class WebCryptoEncodableKey<KF : KeyFormat>(
    private val key: CryptoKey,
    private val keyFormat: (KF) -> String,
) : EncodableKey<KF> {
    override suspend fun encodeTo(format: KF): Buffer {
        return WebCrypto.subtle.exportKeyBinary(
            format = keyFormat(format),
            key = key
        ).await()
    }

    override suspend fun encodeTo(format: KF, output: Buffer): Buffer = encodeTo(format).copyInto(output)
    override fun encodeToBlocking(format: KF): Buffer = nonBlocking()
    override fun encodeToBlocking(format: KF, output: Buffer): Buffer = nonBlocking()
}
