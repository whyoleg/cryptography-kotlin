/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal object Openssl3RsaRaw : Openssl3Rsa<RSA.RAW.PublicKey, RSA.RAW.PrivateKey, RSA.RAW.KeyPair>(), RSA.RAW {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.RAW.KeyPair = RsaRawKeyPair(
        publicKey = RsaRawPublicKey(keyPair),
        privateKey = RsaRawPrivateKey(keyPair),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.RAW.PublicKey =
        RsaRawPublicKey(publicKey)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.RAW.PrivateKey =
        RsaRawPrivateKey(privateKey)

    private class RsaRawKeyPair(
        override val publicKey: RSA.RAW.PublicKey,
        override val privateKey: RSA.RAW.PrivateKey,
    ) : RSA.RAW.KeyPair

    private class RsaRawPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : RsaPublicKey(key), RSA.RAW.PublicKey {
        override fun encryptor(): Encryptor = RsaRawEncryptor(key)
    }

    private class RsaRawPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : RsaPrivateKey(key), RSA.RAW.PrivateKey {
        override fun decryptor(): Decryptor = RsaRawDecryptor(key)
    }
}

private class RsaRawEncryptor(
    private val publicKey: CPointer<EVP_PKEY>,
) : Encryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, publicKey, null))
        try {
            checkError(
                EVP_PKEY_encrypt_init_ex(
                    ctx = context,
                    params = OSSL_PARAM_arrayNotNull(
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "none".cstr.ptr, 0.convert()),
                    )
                )
            )

            val outlen = alloc<size_tVar>()
            checkError(
                EVP_PKEY_encrypt(
                    ctx = context,
                    out = null,
                    outlen = outlen.ptr,
                    `in` = plaintext.safeRefToU(0),
                    inlen = plaintext.size.convert()
                )
            )
            val ciphertext = ByteArray(outlen.value.convert())
            checkError(
                EVP_PKEY_encrypt(
                    ctx = context,
                    out = ciphertext.refToU(0),
                    outlen = outlen.ptr,
                    `in` = plaintext.safeRefToU(0),
                    inlen = plaintext.size.convert()
                )
            )
            ciphertext.ensureSizeExactly(outlen.value.convert())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}

private class RsaRawDecryptor(
    private val privateKey: CPointer<EVP_PKEY>,
) : Decryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
        try {
            checkError(
                EVP_PKEY_decrypt_init_ex(
                    ctx = context,
                    params = OSSL_PARAM_arrayNotNull(
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "none".cstr.ptr, 0.convert()),
                    )
                )
            )

            val outlen = alloc<size_tVar>()
            checkError(
                EVP_PKEY_decrypt(
                    ctx = context,
                    out = null,
                    outlen = outlen.ptr,
                    `in` = ciphertext.safeRefToU(0),
                    inlen = ciphertext.size.convert()
                )
            )
            val plaintext = ByteArray(outlen.value.convert())
            checkError(
                EVP_PKEY_decrypt(
                    ctx = context,
                    out = plaintext.refToU(0),
                    outlen = outlen.ptr,
                    `in` = ciphertext.safeRefToU(0),
                    inlen = ciphertext.size.convert()
                )
            )
            plaintext.ensureSizeExactly(outlen.value.convert())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
