package dev.whyoleg.cryptography.webcrypto.materials

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

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

    override fun encodeToBlocking(format: KF): Buffer = nonBlocking()
}
