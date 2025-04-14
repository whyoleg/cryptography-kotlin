/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.SignatureVerifier
import dev.whyoleg.cryptography.operations.VerifyFunction
import dev.whyoleg.cryptography.providers.base.checkBounds
import dev.whyoleg.cryptography.providers.openssl3.internal.Resource
import dev.whyoleg.cryptography.providers.openssl3.internal.SafeCloseAction
import dev.whyoleg.cryptography.providers.openssl3.internal.SafeCloseable
import dev.whyoleg.cryptography.providers.openssl3.internal.allocArrayOf
import dev.whyoleg.cryptography.providers.openssl3.internal.checkError
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_CTX
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_CTX_free
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_CTX_new
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_fetch
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_init
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.EVP_MAC_update
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.OSSL_PARAM_construct_end
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.OSSL_PARAM_construct_utf8_string
import dev.whyoleg.cryptography.providers.openssl3.internal.safeAddressOf
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.cstr
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned

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

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            val context = context.access()
            val result = signature.usePinned {
                // TODO
            }

            return true
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }
    }
}