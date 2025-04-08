package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Cmac : CMAC {
    private val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

    private lateinit var context: Resource<CPointer<EVP_MAC_CTX>>

    override fun keyGenerator(
        cipherParameters: ByteArray,
        algorithm: String,
    ): KeyGenerator<CMAC.Key> {
        return CmacKeyGenerator(cipherParameters, algorithm)
    }

    private class CmacKeyGenerator(
        private val cipherParameters: ByteArray,
        private val algorithm: String,
    ) : KeyGenerator<CMAC.Key> {
        override fun generateKeyBlocking(): CMAC.Key {
            return CmacKey(cipherParameters, algorithm)
        }
    }

    private class CmacKey(
        private val key: ByteArray,
        private val algorithm: String,
    ) : CMAC.Key {

        init {
            context = Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free)
            key.usePinned {
                checkError(EVP_MAC_init(context.access(), it.safeAddressOf(0).reinterpret(), key.size.convert(), null))
            }
        }

        override fun encodeToByteArrayBlocking(format: CMAC.Key.Format): ByteArray = when (format) {
            CMAC.Key.Format.RAW -> {
                val context = context.access()
                val macSize = EVP_MAC_CTX_get_mac_size(context).convert<Int>()
                val out = ByteArray(macSize)
                checkBounds(out.size, 0, macSize)
                out.usePinned { checkError(EVP_MAC_final(context, it.safeAddressOf(0).reinterpret(), null, macSize.convert())) }
                out
            }
        }

        override fun update(data: ByteArray) {
            val context = context.access()
            data.usePinned { checkError(EVP_MAC_update(context, it.safeAddressOf(0).reinterpret(), data.size.convert())) }
        }

        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)
            val context = context.access()

            source.usePinned {
                checkError(EVP_MAC_update(context, it.safeAddressOf(startIndex).reinterpret(), (endIndex - startIndex).convert()))
            }
        }

        override fun reset() {
            checkError(EVP_MAC_reset(context.access()))
        }
    }
}