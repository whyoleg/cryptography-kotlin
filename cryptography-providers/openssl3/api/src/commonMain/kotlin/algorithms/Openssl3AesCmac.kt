/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.operations.AesCmacWithIvCipher
import dev.whyoleg.cryptography.providers.openssl3.operations.AesCmacWithIvCipherFunction
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

@OptIn(ExperimentalNativeApi::class)
internal object Openssl3AesCmac : AES.CMAC, Openssl3Aes<AES.CMAC.Key>() {
    val mac = checkError(EVP_MAC_fetch(null, "CMAC", null))

    // is it needed at all for `object`?
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(Openssl3Hmac.mac, ::EVP_MAC_free)

    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.CMAC.Key = AesCmacKey(keySize, key)

    private class AesCmacKey(keySize: BinarySize, key: ByteArray) : AES.CMAC.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-CBC"
            AES.Key.Size.B192 -> "AES-192-CBC"
            AES.Key.Size.B256 -> "AES-256-CBC"
            else              -> error("Unsupported key size")
        }
        private val signature = AesCmacSignature(algorithm = algorithm, key = key)
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
        override fun cipherWithIv(padding: Boolean): AesCmacWithIvCipher = AesCmacWithIvCipher(algorithm = algorithm, key = key)
    }
}

@OptIn(UnsafeNumber::class)
@ExperimentalNativeApi
private class AesCmacSignature(
    private val algorithm: String,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {

    private fun createFunction() = AesCmacFunction(
        key = key,
        algorithm = algorithm,
        context = Resource(checkError(EVP_MAC_CTX_new(Openssl3AesCmac.mac)), ::EVP_MAC_CTX_free)
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()

    private class AesCmacFunction(
        private val key: ByteArray,
        private val algorithm: String,
        private val context: Resource<CPointer<EVP_MAC_CTX>>,
    ) : SignFunction, VerifyFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {

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
        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)
            return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        @OptIn(UnsafeNumber::class)
        override fun reset() {
            val context = context.access()
            memScoped {
                val params = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string(
                        "cipher".cstr.ptr,
                        algorithm.cstr.ptr,
                        0.convert()
                    )
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

@OptIn(ExperimentalStdlibApi::class)
@ExperimentalNativeApi
private class AesCmacWithIvCipher(
    private val algorithm: String,
    private val key: ByteArray,
) : AesCmacWithIvCipher {

    private lateinit var cipherFunction: AesCmacWithIvCipherFunction

    override fun initialize() {
        val cipher = when (algorithm) {
            "AES-128-CBC" -> EVP_CIPHER_fetch(null, "AES-128-CBC", null)
            "AES-192-CBC" -> EVP_CIPHER_fetch(null, "AES-192-CBC", null)
            "AES-256-CBC" -> EVP_CIPHER_fetch(null, "AES-256-CBC", null)
            else -> error("Unsupported algorithm: $algorithm")
        }

        cipherFunction = AesCmacWithIvCipherFunction(
            cipher = cipher,
            key = key,
            iv = ByteArray(16), // AES block size
            ivStartIndex = 0,
            encrypt = true
        ) as AesCmacWithIvCipherFunction
        cipherFunction.initialize()
    }

    override fun processBlocking(input: ByteArray, iv: ByteArray): ByteArray {
        return cipherFunction.process(input, iv)
    }

    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return cipherFunction.transform(plaintext)
    }
}