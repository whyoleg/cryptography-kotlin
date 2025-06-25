/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3Hmac : HMAC {
    val mac = checkError(EVP_MAC_fetch(null, "HMAC", null))

    // is it needed at all for `object`?
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(mac, ::EVP_MAC_free)

    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        return HmacKeyDecoder(hashAlgorithm)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        return HmacKeyGenerator(hashAlgorithm, blockSize(hashAlgorithm))
    }
}

private class HmacKeyDecoder(
    private val hashAlgorithm: String,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromByteArrayBlocking(format: HMAC.Key.Format, bytes: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> HmacKey(hashAlgorithm, bytes.copyOf())
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacKeyGenerator(
    private val hashAlgorithm: String,
    private val blockSize: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographySystem.getDefaultRandom().nextBytes(blockSize)
        return HmacKey(hashAlgorithm, key)
    }
}

private class HmacKey(hashAlgorithm: String, private val key: ByteArray) : HMAC.Key {
    private val signature = HmacSignature(hashAlgorithm, key)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacSignature(
    private val hashAlgorithm: String,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {
    private fun createFunction() = HmacFunction(
        hashAlgorithm = hashAlgorithm,
        key = key,
        context = Resource(checkError(EVP_MAC_CTX_new(Openssl3Hmac.mac)), ::EVP_MAC_CTX_free)
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()

    private class HmacFunction(
        private val hashAlgorithm: String,
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
                checkError(EVP_MAC_update(context, it.safeAddressOfU(startIndex), (endIndex - startIndex).convert()))
            }
        }

        @OptIn(UnsafeNumber::class)
        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val context = context.access()
            checkBounds(destination.size, destinationOffset, destinationOffset + macSize)

            destination.usePinned {
                checkError(EVP_MAC_final(context, it.safeAddressOfU(destinationOffset), null, macSize.convert()))
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
                        params = OSSL_PARAM_array(
                            OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert())
                        )
                    )
                )
            }
        }
    }
}
