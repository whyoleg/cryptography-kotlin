package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal object Openssl3RsaPss : Openssl3Rsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(), RSA.PSS {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PSS.KeyPair = RsaPssKeyPair(
        publicKey = RsaPssPublicKey(hashAlgorithm, keyPair),
        privateKey = RsaPssPrivateKey(hashAlgorithm, keyPair),
    )

    override fun wrapPublicKey(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PSS.PublicKey =
        RsaPssPublicKey(hashAlgorithm, keyPair)

    override fun wrapPrivateKey(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PSS.PrivateKey =
        RsaPssPrivateKey(hashAlgorithm, keyPair)


    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        private val hashAlgorithm: String,
        key: CPointer<EVP_PKEY>,
    ) : RsaPublicKey(key), RSA.PSS.PublicKey {
        override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier =
            RsaPssSignatureVerifier(key.upRef(), hashAlgorithm, saltLength.inBytes)
    }

    private class RsaPssPrivateKey(
        private val hashAlgorithm: String,
        key: CPointer<EVP_PKEY>,
    ) : RsaPrivateKey(key), RSA.PSS.PrivateKey {
        override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator =
            RsaPssSignatureGenerator(key.upRef(), hashAlgorithm, saltLength.inBytes)
    }
}

private class RsaPssSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : SignatureGenerator {
    private val cleaner = privateKey.cleaner()

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            checkError(
                EVP_DigestSignInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm,
                    libctx = null,
                    props = null,
                    pkey = privateKey,
                    params = OSSL_PARAM_array(
//                        OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0),
//                        OSSL_PARAM_construct_utf8_string("mgf1-digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0),

                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0),
                        OSSL_PARAM_construct_utf8_string("saltlen".cstr.ptr, saltLengthBytes.toString().cstr.ptr, 0),
                    )
                )
            )

            checkError(EVP_DigestSignUpdate(context, dataInput.safeRefTo(0), dataInput.size.convert()))

            val siglen = alloc<size_tVar>()
            checkError(EVP_DigestSignFinal(context, null, siglen.ptr))
            val signature = ByteArray(siglen.value.convert())
            checkError(EVP_DigestSignFinal(context, signature.refToU(0), siglen.ptr))
            signature.ensureSizeExactly(siglen.value.convert())
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}

private class RsaPssSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
    private val saltLengthBytes: Int,
) : SignatureVerifier {
    private val cleaner = publicKey.cleaner()

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            checkError(
                EVP_DigestVerifyInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm,
                    libctx = null,
                    props = null,
                    pkey = publicKey,
                    params = OSSL_PARAM_array(
                        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pss".cstr.ptr, 0),
                        OSSL_PARAM_construct_utf8_string("saltlen".cstr.ptr, saltLengthBytes.toString().cstr.ptr, 0),
                    )
                )
            )

            checkError(EVP_DigestVerifyUpdate(context, dataInput.safeRefTo(0), dataInput.size.convert()))

            val result = EVP_DigestVerifyFinal(context, signatureInput.safeRefToU(0), signatureInput.size.convert())
            // 0     - means verification failed
            // 1     - means verification succeeded
            // other - means error
            if (result != 0) checkError(result)
            result == 1
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}
