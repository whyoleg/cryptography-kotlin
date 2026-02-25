/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3RsaPss : Openssl3Rsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(
    wrapPublicKey = ::RsaPssPublicKey,
    wrapPrivateKey = ::RsaPssPrivateKey,
    wrapKeyPair = ::RsaPssKeyPair,
), RSA.PSS {
    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        key: CPointer<EVP_PKEY>,
        digest: CryptographyAlgorithmId<Digest>,
    ) : RsaPublicKey(key, digest), RSA.PSS.PublicKey {

        override fun signatureVerifier(): SignatureVerifier {
            val hashAlgorithm = hashAlgorithmName(digest)
            val md = EVP_MD_fetch(null, hashAlgorithm, null)
            val digestSize = EVP_MD_get_size(md)
            EVP_MD_free(md)
            return signatureVerifier(digestSize.bytes)
        }

        override fun signatureVerifier(saltSize: BinarySize): SignatureVerifier =
            RsaPssSignatureVerifier(key, hashAlgorithmName(digest), saltSize.inBytes)
    }

    private class RsaPssPrivateKey(
        key: CPointer<EVP_PKEY>,
        digest: CryptographyAlgorithmId<Digest>,
        publicKey: RSA.PSS.PublicKey?,
    ) : RsaPrivateKey(key, digest, publicKey), RSA.PSS.PrivateKey {

        override fun signatureGenerator(): SignatureGenerator {
            val hashAlgorithm = hashAlgorithmName(digest)
            val md = EVP_MD_fetch(null, hashAlgorithm, null)
            val digestSize = EVP_MD_get_size(md)
            EVP_MD_free(md)
            return signatureGenerator(digestSize.bytes)
        }

        override fun signatureGenerator(saltSize: BinarySize): SignatureGenerator =
            RsaPssSignatureGenerator(key, hashAlgorithmName(digest), saltSize.inBytes)
    }
}

private class RsaPssSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0.convert()),
        OSSL_PARAM_construct_int("saltlen".cstr.ptr, alloc(saltLengthBytes).ptr),
    )
}

private class RsaPssSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0.convert()),
        OSSL_PARAM_construct_int("saltlen".cstr.ptr, alloc(saltLengthBytes).ptr),
    )
}

