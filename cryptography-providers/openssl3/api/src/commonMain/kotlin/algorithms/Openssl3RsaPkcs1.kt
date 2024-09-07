/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal object Openssl3RsaPkcs1 : Openssl3Rsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(), RSA.PKCS1 {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PKCS1.KeyPair = RsaPkcs1KeyPair(
        publicKey = RsaPkcs1PublicKey(keyPair, hashAlgorithm),
        privateKey = RsaPkcs1PrivateKey(keyPair, hashAlgorithm),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.PKCS1.PublicKey =
        RsaPkcs1PublicKey(publicKey, hashAlgorithm)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.PKCS1.PrivateKey =
        RsaPkcs1PrivateKey(privateKey, hashAlgorithm)

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = RsaPkcs1SignatureVerifier(key, hashAlgorithm)
        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(key)
    }

    private class RsaPkcs1PrivateKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPrivateKey(key), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = RsaPkcs1SignatureGenerator(key, hashAlgorithm)
        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(key)
    }
}

private class RsaPkcs1SignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
    )
}

private class RsaPkcs1SignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
    )
}

private class RsaPkcs1Encryptor(
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
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
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

private class RsaPkcs1Decryptor(
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
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
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
