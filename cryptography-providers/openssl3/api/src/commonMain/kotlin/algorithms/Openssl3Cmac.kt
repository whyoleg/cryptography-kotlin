package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.base.checkBounds
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Cmac : CMAC {
    private val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

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
        override fun generateKeyBlocking(): CMAC.Key = CmacKey(
            key = cipherParameters,
            algorithm = algorithm,
            context = Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free)
        )
    }

    @OptIn(UnsafeNumber::class)
    private class CmacKey(
        private val key: ByteArray,
        private val algorithm: String,
        private val context: Resource<CPointer<EVP_MAC_CTX>>,
    ) : CMAC.Key {

        init {
            validateKeySize(key)
            reset()
        }

        override fun update(data: ByteArray) {
            val context = context.access()
            data.usePinned {
                checkError(
                    EVP_MAC_update(
                        ctx = context,
                        data = it.safeAddressOf(0).reinterpret(),
                        datalen = data.size.convert()
                    )
                )
            }
        }

        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)
            val context = context.access()

            source.usePinned {
                checkError(
                    EVP_MAC_update(
                        ctx = context,
                        data = it.safeAddressOf(startIndex).reinterpret(),
                        datalen = (endIndex - startIndex).convert()
                    )
                )
            }
        }

        override fun encodeToByteArrayBlocking(format: CMAC.Key.Format): ByteArray = when (format) {
            CMAC.Key.Format.RAW -> {
                val context = context.access()
                val macSize = EVP_MAC_CTX_get_mac_size(context).convert<Int>()
                val out = ByteArray(macSize)
                out.usePinned {
                    checkError(
                        EVP_MAC_final(
                            ctx = context,
                            out = it.safeAddressOf(0).reinterpret(),
                            outl = null,
                            outsize = macSize.convert()
                        )
                    )
                }
                out
            }
        }

        override fun reset() {
            val context = context.access()

            // Define the cipher parameter
            val cipherString = "AES-128-CBC"
            memScoped {
                val params = allocArrayOf(
                    OSSL_PARAM_construct_utf8_string(
                        "cipher".cstr.ptr,
                        cipherString.cstr.ptr,
                        0.convert()
                    ),
                    OSSL_PARAM_construct_end()
                )

                // Initialize the CMAC context with the key and parameters
                key.usePinned {
                    checkError(
                        EVP_MAC_init(
                            ctx = context,
                            key = it.addressOf(0).reinterpret(),
                            keylen = key.size.convert(),
                            params = params
                        )
                    )
                }
            }
        }

        private fun validateKeySize(key: ByteArray) {
            if (key.size !in listOf(16, 24, 32)) {
                throw IllegalArgumentException("Invalid AES key size: ${key.size * 8} bits. Expected 128, 192, or 256 bits.")
            }
        }
    }
}