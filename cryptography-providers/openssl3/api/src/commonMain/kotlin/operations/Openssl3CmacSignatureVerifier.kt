/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal class Openssl3CmacSignatureVerifier(
    private val key: ByteArray,
    private val algorithm: String = "AES-128-CBC",
) : SignatureVerifier {

    private val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    override fun createVerifyFunction(): VerifyFunction {
        return Openssl3CmacVerifyFunction(Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free))
    }

    private inner class Openssl3CmacVerifyFunction(
        private val context: Resource<CPointer<EVP_MAC_CTX>>,
    ) : VerifyFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {

        init {
            reset()
        }

        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            // Implementation for updating the CMAC with the provided data
            checkBounds(source.size, startIndex, endIndex)
            val context = context.access()
            source.usePinned {
                checkError(
                    EVP_MAC_update(
                        ctx = context,
                        data = it.safeAddressOf(0).reinterpret(),
                        datalen = source.size.convert()
                    )
                )
            }
        }

        @OptIn(UnsafeNumber::class)
        override fun reset() {
            val context = context.access()
            memScoped {
                val params = allocArrayOf(
                    OSSL_PARAM_construct_utf8_string(
                        "cipher".cstr.ptr,
                        algorithm.cstr.ptr,
                        0.convert()
                    ),
                    OSSL_PARAM_construct_end()
                )

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

        @OptIn(UnsafeNumber::class)
        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            val context = context.access()
            val computedMac = ByteArray(EVP_MAC_CTX_get_mac_size(context).convert<Int>())

            computedMac.usePinned { pinnedMac ->
                checkError(
                    EVP_MAC_final(
                        ctx = context,
                        out = pinnedMac.addressOf(0).reinterpret(),
                        outl = null,
                        outsize = computedMac.size.convert()
                    )
                )
            }

            val isValid = computedMac.contentEquals(signature.copyOfRange(startIndex, endIndex))
            if (!isValid) throw IllegalArgumentException("Invalid signature")
            return isValid
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }
    }
}