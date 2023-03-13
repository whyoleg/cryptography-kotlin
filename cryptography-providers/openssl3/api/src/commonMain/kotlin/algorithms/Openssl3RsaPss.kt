package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.openssl3.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal object Openssl3RsaPss : Openssl3Rsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(), RSA.PSS {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PSS.KeyPair = RsaPssKeyPair(
        publicKey = RsaPssPublicKey(keyPair, hashAlgorithm),
        privateKey = RsaPssPrivateKey(keyPair, hashAlgorithm),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.PSS.PublicKey =
        RsaPssPublicKey(publicKey, hashAlgorithm)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.PSS.PrivateKey =
        RsaPssPrivateKey(privateKey, hashAlgorithm)

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.PSS.PublicKey {
        override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier =
            RsaPssSignatureVerifier(key, hashAlgorithm, saltLength.inBytes)
    }

    private class RsaPssPrivateKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPrivateKey(key), RSA.PSS.PrivateKey {
        override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator =
            RsaPssSignatureGenerator(key, hashAlgorithm, saltLength.inBytes)
    }
}

private class RsaPssSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0),
        OSSL_PARAM_construct_int("saltlen".cstr.ptr, alloc(saltLengthBytes).ptr),
    )
}

private class RsaPssSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0),
        OSSL_PARAM_construct_int("saltlen".cstr.ptr, alloc(saltLengthBytes).ptr),
    )
}
