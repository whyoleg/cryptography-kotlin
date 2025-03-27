package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

internal object Openssl3Cmac : CMAC {
    private val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

    private lateinit var context: Resource<CPointer<EVP_MAC_CTX>>

    override fun init(parameters: ByteArray) {
        context = Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free)
        parameters.usePinned {
            checkError(EVP_MAC_init(context.access(), it.addressOf(0), parameters.size.convert(), null))
        }
    }

    override fun update(data: ByteArray) {
        data.usePinned {
            checkError(EVP_MAC_update(context.access(), it.addressOf(0), data.size.convert()))
        }
    }

    override fun doFinal(): ByteArray {
        val macSize = EVP_MAC_CTX_get_mac_size(context.access()).convert<Int>()
        val result = ByteArray(macSize)
        result.usePinned {
            checkError(EVP_MAC_final(context.access(), it.addressOf(0), null, macSize.convert()))
        }
        return result
    }

    override fun reset() {
        checkError(EVP_MAC_reset(context.access()))
    }
}