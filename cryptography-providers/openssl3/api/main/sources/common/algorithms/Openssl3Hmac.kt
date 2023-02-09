package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal object Openssl3Hmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        //TODO: don't do it here - pool/cache
        val md = EVP_MD_fetch(null, hashAlgorithm, null)
        val keySizeBytes = EVP_MD_get_block_size(md)
        EVP_MD_free(md)
        return HmacKeyDecoder(hashAlgorithm, keySizeBytes)
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        val hashAlgorithm = hashAlgorithm(digest)
        //TODO: don't do it here - pool/cache
        val md = EVP_MD_fetch(null, hashAlgorithm, null)
        val keySizeBytes = EVP_MD_get_block_size(md)
        EVP_MD_free(md)
        return HmacKeyGenerator(hashAlgorithm, keySizeBytes)
    }
}

private class HmacKeyDecoder(
    private val hashAlgorithm: String,
    private val keySizeBytes: Int,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromBlocking(format: HMAC.Key.Format, input: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> {
            require(input.size == keySizeBytes) { "Invalid key size: ${input.size}, expected: $keySizeBytes" }
            wrapKey(hashAlgorithm, input.copyOf())
        }
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacKeyGenerator(
    private val hashAlgorithm: String,
    private val keySizeBytes: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(hashAlgorithm, key)
    }
}

private fun wrapKey(
    hashAlgorithm: String,
    key: ByteArray,
): HMAC.Key = object : HMAC.Key {
    private val signature = HmacSignature(hashAlgorithm, key)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacSignature(
    private val hashAlgorithm: String,
    private val key: ByteArray,
) : SignatureGenerator, SignatureVerifier {

    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = memScoped {
        //TODO: pool it? use EVP_MAC_up_ref?
        val mac = checkNotNull(EVP_MAC_fetch(null, "HMAC", null)) { "HMAC is not supported" }
        val context = checkNotNull(EVP_MAC_CTX_new(mac)) { "Can't create MAC context" }
        try {
            checkError(EVP_MAC_init_HMAC(context, key.refToU(0), key.size.convert(), hashAlgorithm))
            checkError(EVP_MAC_update(context, dataInput.safeRefToU(0), dataInput.size.convert()))
            val signature = ByteArray(checkError(EVP_MAC_CTX_get_mac_size(context)).convert())
            //TODO: check is `outl` needed?
            checkError(EVP_MAC_final(context, signature.refToU(0), null, signature.size.convert()))
            signature
        } finally {
            EVP_MAC_CTX_free(context)
            EVP_MAC_free(mac)
        }
    }

    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean {
        return generateSignatureBlocking(dataInput).contentEquals(signatureInput)
    }
}
