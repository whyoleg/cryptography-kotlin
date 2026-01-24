/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal abstract class EvpMac(
    private val mac: CPointer<EVP_MAC>,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {
    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    private fun createFunction() = MacFunction(
        key = key,
        context = Resource(checkError(EVP_MAC_CTX_new(mac)), ::EVP_MAC_CTX_free)
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()

    private inner class MacFunction(
        private val key: ByteArray,
        private val context: Resource<CPointer<EVP_MAC_CTX>>,
    ) : SignFunction, VerifyFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
        @OptIn(UnsafeNumber::class)
        private val macSize get() = EVP_MAC_CTX_get_mac_size(context.access()).convert<Int>()

        init {
            reset()
        }

        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)
            val context = context.access()

            source.usePinned {
                checkError(
                    EVP_MAC_update(
                        ctx = context,
                        data = it.safeAddressOfU(startIndex),
                        datalen = (endIndex - startIndex).convert()
                    )
                )
            }
        }

        @OptIn(UnsafeNumber::class)
        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val context = context.access()
            checkBounds(destination.size, destinationOffset, destinationOffset + macSize)

            destination.usePinned {
                checkError(
                    EVP_MAC_final(
                        ctx = context,
                        out = it.safeAddressOfU(destinationOffset),
                        outl = null,
                        outsize = macSize.convert()
                    )
                )
            }
            return macSize
        }

        override fun signToByteArray(): ByteArray {
            val signature = ByteArray(macSize)
            signIntoByteArray(signature)
            return signature
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)
            return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        @OptIn(UnsafeNumber::class)
        override fun reset(): Unit = memScoped {
            val context = context.access()
            key.usePinned {
                checkError(
                    EVP_MAC_init(
                        ctx = context,
                        key = it.safeAddressOfU(0),
                        keylen = key.size.convert(),
                        params = createParams()
                    )
                )
            }
        }
    }
}
