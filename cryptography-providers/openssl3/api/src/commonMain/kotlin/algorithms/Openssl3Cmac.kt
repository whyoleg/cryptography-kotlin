package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
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

    override fun init(parameters: ByteArray) {
        context = Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free)
        parameters.usePinned {
            checkError(EVP_MAC_init(context.access(), it.safeAddressOf(0).reinterpret(), parameters.size.convert(), null))
        }
    }

    override fun update(data: ByteArray) {
        val context = context.access()
        data.usePinned {
            checkError(EVP_MAC_update(context, it.safeAddressOf(0).reinterpret(), data.size.convert()))
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)
        val context = context.access()

        source.usePinned {
            checkError(EVP_MAC_update(context, it.safeAddressOf(startIndex).reinterpret(), (endIndex - startIndex).convert()))
        }
    }

    override fun doFinal(): ByteArray {
        val context = context.access()
        val macSize = EVP_MAC_CTX_get_mac_size(context).convert<Int>()
        val result = ByteArray(macSize)
        result.usePinned {
            checkError(EVP_MAC_final(context, it.safeAddressOf(0).reinterpret(), null, macSize.convert()))
        }
        return result
    }

    override fun doFinal(out: ByteArray, offset: Int) {
        val context = context.access()
        val macSize = EVP_MAC_CTX_get_mac_size(context).convert<Int>()
        checkBounds(out.size, offset, offset + macSize)
        out.usePinned {
            checkError(EVP_MAC_final(context, it.safeAddressOf(offset).reinterpret(), null, macSize.convert()))
        }
    }

    override fun reset() {
        checkError(EVP_MAC_reset(context.access()))
    }
}