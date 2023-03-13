package dev.whyoleg.cryptography.openssl3.operations

import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3DigestSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : SignatureVerifier {
    private val cleaner = publicKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

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
                    params = createParams()
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
