package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.native.internal.*

internal object Openssl3Ecdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        TODO("Not yet implemented")
    }

    override fun privateKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        TODO("Not yet implemented")
    }

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> = EcKeyGenerator(curve)

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : KeyGenerator<ECDSA.KeyPair> {

        override fun generateKeyBlocking(): ECDSA.KeyPair = memScoped {
            val context = checkNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null)) { "Failed to create PKEY_CTX context" }
            try {
                checkError(EVP_PKEY_keygen_init(context))
                checkError(EVP_PKEY_CTX_set_params_ECDSA(context, curve.name))

                val keysVar = nativeHeap.alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(context, keysVar.ptr)) { nativeHeap.free(keysVar) }
                val keys = checkNotNull(keysVar.value) { "Failed to generate key pair" }
                EcKeyPair(EcPublicKey(keys), EcPrivateKey(keys)).also {
                    EVP_PKEY_free(keys) // free keys because they are already copied to key pair
                }
            } finally {
                EVP_PKEY_CTX_free(context)
            }
        }
    }

    private class EcKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcPrivateKey(
        private val privateKey: CPointer<EVP_PKEY>,
    ) : ECDSA.PrivateKey {
        init {
            checkError(EVP_PKEY_up_ref(privateKey))
        }

        @OptIn(ExperimentalStdlibApi::class)
        private val cleaner = createCleaner(privateKey, ::EVP_PKEY_free)

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureGenerator(privateKey, hashAlgorithm(digest))
        }

        override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray {
            TODO("Not yet implemented")
        }
    }

    private class EcPublicKey(
        private val publicKey: CPointer<EVP_PKEY>,
    ) : ECDSA.PublicKey {
        init {
            checkError(EVP_PKEY_up_ref(publicKey))
        }

        @OptIn(ExperimentalStdlibApi::class)
        private val cleaner = createCleaner(publicKey, ::EVP_PKEY_free)

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureVerifier(publicKey, hashAlgorithm(digest))
        }

        override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray {
            TODO("Not yet implemented")
        }
    }
}

private class EcdsaSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : SignatureGenerator {

    init {
        checkError(EVP_PKEY_up_ref(privateKey))
    }

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(privateKey, ::EVP_PKEY_free)

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = memScoped {
        val context = checkNotNull(EVP_MD_CTX_new()) { "Failed to create MD context" }
        try {
            checkError(
                EVP_DigestSignInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm,
                    libctx = null,
                    props = null,
                    pkey = privateKey,
                    params = null
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

private class EcdsaSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : SignatureVerifier {

    init {
        checkError(EVP_PKEY_up_ref(publicKey))
    }

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(publicKey, ::EVP_PKEY_free)

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = memScoped {
        val context = checkNotNull(EVP_MD_CTX_new()) { "Failed to create MD context" }
        try {
            checkError(
                EVP_DigestVerifyInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm,
                    libctx = null,
                    props = null,
                    pkey = publicKey,
                    params = null
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
