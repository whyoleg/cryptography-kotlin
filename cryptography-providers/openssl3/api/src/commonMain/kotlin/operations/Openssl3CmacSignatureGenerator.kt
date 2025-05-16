/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal class Openssl3CmacSignatureGenerator(
    private val key: ByteArray,
    private val algorithm: String = "AES-128-CBC",
) : SignatureGenerator {
    private val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    override fun createSignFunction(): SignFunction {
        return Openssl3CmacSignFunction(Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free))
    }

    private inner class Openssl3CmacSignFunction(
        private val context: Resource<CPointer<EVP_MAC_CTX>>,
    ) : SignFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {

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

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val signature = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
            signature.copyInto(destination, destinationOffset, destinationOffset)
            return signature.size
        }

        @OptIn(UnsafeNumber::class)
        override fun signToByteArray(): ByteArray {
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
            return out
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
    }
}