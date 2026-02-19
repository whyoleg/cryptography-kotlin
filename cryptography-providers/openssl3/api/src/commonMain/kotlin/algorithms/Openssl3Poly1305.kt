/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

private const val keySize: Int = 32

internal object Openssl3Poly1305 : Poly1305 {
    val mac = checkError(EVP_MAC_fetch(null, "POLY1305", null))

    // is it needed at all for `object`?
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

    override fun keyDecoder(): Decoder<Poly1305.Key.Format, Poly1305.Key> = Poly1305KeyDecoder()
    override fun keyGenerator(): KeyGenerator<Poly1305.Key> = Poly1305KeyGenerator()
}

private class Poly1305KeyDecoder : Decoder<Poly1305.Key.Format, Poly1305.Key> {
    override fun decodeFromByteArrayBlocking(format: Poly1305.Key.Format, bytes: ByteArray): Poly1305.Key = when (format) {
        Poly1305.Key.Format.RAW -> {
            require(bytes.size == keySize) { "Poly1305 key size must be 256 bits" }
            Poly1305Key(bytes.copyOf())
        }
    }
}

private class Poly1305KeyGenerator : KeyGenerator<Poly1305.Key> {
    override fun generateKeyBlocking(): Poly1305.Key {
        val key = CryptographySystem.getDefaultRandom().nextBytes(keySize)
        return Poly1305Key(key)
    }
}

private class Poly1305Key(private val key: ByteArray) : Poly1305.Key {
    private val signature = Poly1305Signature(key)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: Poly1305.Key.Format): ByteArray = when (format) {
        Poly1305.Key.Format.RAW -> key.copyOf()
    }
}

private class Poly1305Signature(key: ByteArray) : EvpMac(Openssl3Poly1305.mac, key) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
