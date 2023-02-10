package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.native.internal.*

internal object Openssl3Ecdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> = EcPublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> = EcPrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> = EcKeyGenerator(curve)

    private class EcPrivateKeyDecoder(
        private val curve: EC.Curve?,
    ) : KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> {
        override fun decodeFromBlocking(format: EC.PrivateKey.Format, input: ByteArray): ECDSA.PrivateKey = memScoped {
            //TODO: validate curve!!!
            val stringFormat = when (format) {
                EC.PrivateKey.Format.DER -> "DER"
                EC.PrivateKey.Format.PEM -> "PEM"
                EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
            }
            nativeHeap.safeAlloc<CPointerVar<EVP_PKEY>, _> { pkey ->
                val context = checkError(
                    OSSL_DECODER_CTX_new_for_pkey(
                        pkey = pkey.ptr,
                        input_type = stringFormat.cstr.ptr,
                        input_struct = "PrivateKeyInfo".cstr.ptr,
                        keytype = "EC".cstr.ptr,
                        selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                        libctx = null,
                        propquery = null
                    )
                )
                //println("PRI_DECODE: $format")
                //println("PRI_DECODE_SIZE[1]: ${input.size}")
                try {
                    val pdataLenVar = alloc<size_tVar> {
                        value = input.size.convert()
                    }
                    val pdataVar = alloc<CPointerVar<UByteVar>> {
                        value = allocArrayOf(input).reinterpret()
                    }
                    checkError(OSSL_DECODER_from_data(context, pdataVar.ptr, pdataLenVar.ptr))
                    //println("PRI_DECODE_SIZE[2]: ${pdataLenVar.value}")
                    EcPrivateKey(checkNotNull(pkey.value))
                } finally {
                    OSSL_DECODER_CTX_free(context)
                }
            }
        }
    }

    private class EcPublicKeyDecoder(
        private val curve: EC.Curve?,
    ) : KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> {
        override fun decodeFromBlocking(format: EC.PublicKey.Format, input: ByteArray): ECDSA.PublicKey = memScoped {
            //TODO: validate curve!!!
            val stringFormat = when (format) {
                EC.PublicKey.Format.RAW -> TODO("will be be supported later")
                EC.PublicKey.Format.DER -> "DER"
                EC.PublicKey.Format.PEM -> "PEM"
                EC.PublicKey.Format.JWK -> error("JWK format is not supported")
            }
            nativeHeap.safeAlloc<CPointerVar<EVP_PKEY>, _> { pkey ->
                val context = checkError(
                    OSSL_DECODER_CTX_new_for_pkey(
                        pkey = pkey.ptr,
                        input_type = stringFormat.cstr.ptr,
                        input_struct = if (stringFormat == "EC") "EC".cstr.ptr else "SubjectPublicKeyInfo".cstr.ptr,
                        keytype = "EC".cstr.ptr,
                        selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                        libctx = null,
                        propquery = null
                    )
                )
                //println("PUB_DECODE: $format")
                //println("PUB_DECODE_SIZE[1]: ${input.size}")
                try {
                    val pdataLenVar = alloc<size_tVar> {
                        value = input.size.convert()
                    }
                    val pdataVar = alloc<CPointerVar<UByteVar>> {
                        value = allocArrayOf(input).reinterpret()
                    }
                    checkError(OSSL_DECODER_from_data(context, pdataVar.ptr, pdataLenVar.ptr))
                    //println("PUB_DECODE_SIZE[2]: ${pdataLenVar.value}")
                    EcPublicKey(checkNotNull(pkey.value))
                } finally {
                    OSSL_DECODER_CTX_free(context)
                }
            }
        }
    }

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : KeyGenerator<ECDSA.KeyPair> {

        override fun generateKeyBlocking(): ECDSA.KeyPair = memScoped {
            val context = checkNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null)) { "Failed to create PKEY_CTX context" }
            try {
                val params = OSSL_PARAM_array(
                    OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0)
                )
                checkError(EVP_PKEY_keygen_init(context))
                checkError(EVP_PKEY_CTX_set_params(context, params))
                nativeHeap.safeAlloc<CPointerVar<EVP_PKEY>, _> { keys ->
                    checkError(EVP_PKEY_generate(context, keys.ptr))
                    val keyPair = checkNotNull(keys.value) { "Failed to generate key pair" }
                    checkError(EVP_PKEY_up_ref(keyPair)) //we need to 2 references to keys
                    EcKeyPair(EcPublicKey(keyPair), EcPrivateKey(keyPair))
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

        @OptIn(ExperimentalStdlibApi::class)
        private val cleaner = createCleaner(privateKey, ::EVP_PKEY_free)

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureGenerator(privateKey, hashAlgorithm(digest))
        }

        override fun encodeToBlocking(format: EC.PrivateKey.Format): ByteArray = memScoped {
            val stringFormat = when (format) {
                EC.PrivateKey.Format.DER -> "DER"
                EC.PrivateKey.Format.PEM -> "PEM"
                EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
            }
            val context = checkError(
                OSSL_ENCODER_CTX_new_for_pkey(
                    pkey = privateKey,
                    selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                    output_type = stringFormat.cstr.ptr,
                    output_struct = "PrivateKeyInfo".cstr.ptr,
                    propquery = null
                )
            )
            try {
                //println("PRI_ENCODE: $format")
                val pdataLenVar = alloc<size_tVar>()
                val pdataVar = alloc<CPointerVar<UByteVar>>()
                checkError(OSSL_ENCODER_to_data(context, pdataVar.ptr, pdataLenVar.ptr))
                //println("PRI_ENCODE SIZE[1]: ${pdataLenVar.value}")
                pdataVar.value!!.readBytes(pdataLenVar.value.convert()).also {
                    //println("PRI_ENCODE SIZE[2]: ${it.size}")
                }
            } finally {
                OSSL_ENCODER_CTX_free(context)
            }
        }
    }

    private class EcPublicKey(
        private val publicKey: CPointer<EVP_PKEY>,
    ) : ECDSA.PublicKey {

        @OptIn(ExperimentalStdlibApi::class)
        private val cleaner = createCleaner(publicKey, ::EVP_PKEY_free)

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureVerifier(publicKey, hashAlgorithm(digest))
        }

        override fun encodeToBlocking(format: EC.PublicKey.Format): ByteArray = memScoped {
            val stringFormat = when (format) {
                EC.PublicKey.Format.RAW -> "BLOB"
                EC.PublicKey.Format.DER -> "DER"
                EC.PublicKey.Format.PEM -> "PEM"
                EC.PublicKey.Format.JWK -> error("JWK format is not supported")
            }
            val context = checkError(
                OSSL_ENCODER_CTX_new_for_pkey(
                    pkey = publicKey,
                    selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                    output_type = stringFormat.cstr.ptr,
                    output_struct = if (stringFormat == "BLOB") null else "SubjectPublicKeyInfo".cstr.ptr,
                    propquery = null
                )
            )
            try {
                //println("PUB_ENCODE: $format")
                val pdataLenVar = alloc<size_tVar>()
                //TODO: may be this is wrong :)
                val pdataVar = alloc<CPointerVar<UByteVar>>()
                checkError(OSSL_ENCODER_to_data(context, pdataVar.ptr, pdataLenVar.ptr))
                //println("PUB_ENCODE SIZE[1]: ${pdataLenVar.value}")
                pdataVar.value!!.readBytes(pdataLenVar.value.convert()).also {
                    //println("PUB_ENCODE SIZE[2]: ${it.size}")
                }
            } finally {
                OSSL_ENCODER_CTX_free(context)
            }
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
