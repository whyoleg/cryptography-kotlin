/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.test

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.test.*

@OptIn(UnsafeNumber::class)
abstract class LibCrypto3Test {

    @Test
    fun testVersion() {
        assertEquals(3, OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString()!!.first().digitToInt())
        assertEquals(3, OPENSSL_version_major().toInt())
    }

    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun testSha() {
        val md = EVP_MD_fetch(null, "SHA256", null)
        try {
            val context = EVP_MD_CTX_new()
            try {
                val data = "Hello World".encodeToByteArray()
                val digest = ByteArray(32)

                check(EVP_DigestInit(context, md) == 1)
                check(EVP_DigestUpdate(context, data.refTo(0), data.size.convert()) == 1)
                check(EVP_DigestFinal(context, digest.asUByteArray().refTo(0), null) == 1)

                assertEquals("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", printHexBinary(digest))
            } finally {
                EVP_MD_CTX_free(context)
            }
        } finally {
            EVP_MD_free(md)
        }
    }

    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun testHmac(): Unit = memScoped {
        val dataInput = "Hi There".encodeToByteArray()
        val hashAlgorithm = "SHA256"
        val key = parseHexBinary("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

        val mac = EVP_MAC_fetch(null, "HMAC", null)
        val context = EVP_MAC_CTX_new(mac)
        try {
            checkError(
                EVP_MAC_init(
                    ctx = context,
                    key = key.asUByteArray().refTo(0),
                    keylen = key.size.convert(),
                    params = OSSL_PARAM_array(
                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0U)
                    )
                )
            )
            val signature = ByteArray(EVP_MAC_CTX_get_mac_size(context).convert())

            checkError(EVP_MAC_update(context, dataInput.fixEmpty().asUByteArray().refTo(0), dataInput.size.convert()))
            checkError(EVP_MAC_final(context, signature.asUByteArray().refTo(0), null, signature.size.convert()))

            assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", printHexBinary(signature))
        } finally {
            EVP_MAC_CTX_free(context)
            EVP_MAC_free(mac)
        }
    }

    @Test
    @OptIn(ExperimentalUnsignedTypes::class)
    fun testEcdsa() {
        val dataInput = "Hi There".encodeToByteArray()

        val pkey = memScoped {
            val context = checkNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null))
            try {
                checkError(EVP_PKEY_keygen_init(context))
                checkError(
                    EVP_PKEY_CTX_set_params(
                        context, OSSL_PARAM_array(
                            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, "P-521".cstr.ptr, 0U)
                        )
                    )
                )
                val pkeyVar = allocPointerTo<EVP_PKEY>()

                checkError(EVP_PKEY_generate(context, pkeyVar.ptr))
                checkNotNull(pkeyVar.value)
            } finally {
                EVP_PKEY_CTX_free(context)
            }
        }

        checkError(EVP_PKEY_up_ref(pkey))

        val signatureInput = memScoped {
            val context = checkNotNull(EVP_MD_CTX_new())
            try {
                checkError(
                    EVP_DigestSignInit_ex(
                        ctx = context,
                        pctx = null,
                        mdname = "SHA256",
                        libctx = null,
                        props = null,
                        pkey = pkey,
                        params = null
                    )
                )

                checkError(EVP_DigestSignUpdate(context, dataInput.refTo(0), dataInput.size.convert()))

                val siglen = alloc<size_tVar>()
                checkError(EVP_DigestSignFinal(context, null, siglen.ptr))
                val signature = ByteArray(siglen.value.convert())
                checkError(EVP_DigestSignFinal(context, signature.asUByteArray().refTo(0), siglen.ptr))
                signature.copyOf(siglen.value.convert())
            } finally {
                EVP_MD_CTX_free(context)
            }
        }

        EVP_PKEY_free(pkey)

        val result = memScoped {
            val context = checkNotNull(EVP_MD_CTX_new())
            try {
                checkError(
                    EVP_DigestVerifyInit_ex(
                        ctx = context,
                        pctx = null,
                        mdname = "SHA256",
                        libctx = null,
                        props = null,
                        pkey = pkey,
                        params = null
                    )
                )

                checkError(EVP_DigestVerifyUpdate(context, dataInput.refTo(0), dataInput.size.convert()))

                val result = EVP_DigestVerifyFinal(context, signatureInput.asUByteArray().refTo(0), signatureInput.size.convert())
                // 0     - means verification failed
                // 1     - means verification succeeded
                // other - means error
                if (result != 0) checkError(result)
                result == 1
            } finally {
                EVP_MD_CTX_free(context)
            }
        }

        EVP_PKEY_free(pkey)

        assertTrue(EVP_PKEY_up_ref(pkey) == 0)

        assertTrue(result)
    }
}
