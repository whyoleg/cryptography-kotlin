/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal object Openssl3RsaOaep : Openssl3Rsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(), RSA.OAEP {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.OAEP.KeyPair = RsaOaepKeyPair(
        publicKey = RsaOaepPublicKey(keyPair, hashAlgorithm),
        privateKey = RsaOaepPrivateKey(keyPair, hashAlgorithm),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.OAEP.PublicKey =
        RsaOaepPublicKey(publicKey, hashAlgorithm)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.OAEP.PrivateKey =
        RsaOaepPrivateKey(privateKey, hashAlgorithm)

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(
        key: CPointer<EVP_PKEY>,
        hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.OAEP.PublicKey {
        private val encryptor = RsaOaepEncryptor(key, hashAlgorithm)
        override fun encryptor(): AuthenticatedEncryptor = encryptor
    }

    private class RsaOaepPrivateKey(
        key: CPointer<EVP_PKEY>,
        hashAlgorithm: String,
    ) : RsaPrivateKey(key), RSA.OAEP.PrivateKey {
        private val decryptor = RsaOaepDecryptor(key, hashAlgorithm)
        override fun decryptor(): AuthenticatedDecryptor = decryptor
    }
}

private class RsaOaepEncryptor(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : AuthenticatedEncryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, publicKey, null))
        try {
            checkError(
                EVP_PKEY_encrypt_init_ex(
                    ctx = context,
                    params = OSSL_PARAM_arrayNotNull(
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "oaep".cstr.ptr, 0.convert()),
                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert()),
                        associatedData?.let { OSSL_PARAM_construct_octet_string("oaep-label".cstr.ptr, it.safeRefTo(0), it.size.convert()) }
                    )
                )
            )

            val outlen = alloc<size_tVar>()
            checkError(
                EVP_PKEY_encrypt(
                    ctx = context,
                    out = null,
                    outlen = outlen.ptr,
                    `in` = plaintextInput.safeRefToU(0),
                    inlen = plaintextInput.size.convert()
                )
            )
            val ciphertext = ByteArray(outlen.value.convert())
            checkError(
                EVP_PKEY_encrypt(
                    ctx = context,
                    out = ciphertext.refToU(0),
                    outlen = outlen.ptr,
                    `in` = plaintextInput.safeRefToU(0),
                    inlen = plaintextInput.size.convert()
                )
            )
            ciphertext.ensureSizeExactly(outlen.value.convert())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}

private class RsaOaepDecryptor(
    private val privateKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : AuthenticatedDecryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
        try {
            checkError(
                EVP_PKEY_decrypt_init_ex(
                    ctx = context,
                    params = OSSL_PARAM_arrayNotNull(
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "oaep".cstr.ptr, 0.convert()),
                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert()),
                        associatedData?.let { OSSL_PARAM_construct_octet_string("oaep-label".cstr.ptr, it.safeRefTo(0), it.size.convert()) }
                    )
                )
            )

            val outlen = alloc<size_tVar>()
            checkError(
                EVP_PKEY_decrypt(
                    ctx = context,
                    out = null,
                    outlen = outlen.ptr,
                    `in` = ciphertextInput.safeRefToU(0),
                    inlen = ciphertextInput.size.convert()
                )
            )
            val plaintext = ByteArray(outlen.value.convert())
            checkError(
                EVP_PKEY_decrypt(
                    ctx = context,
                    out = plaintext.refToU(0),
                    outlen = outlen.ptr,
                    `in` = ciphertextInput.safeRefToU(0),
                    inlen = ciphertextInput.size.convert()
                )
            )
            plaintext.ensureSizeExactly(outlen.value.convert())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
