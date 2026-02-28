/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.checkBounds
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.cinterop.*

internal object Openssl3Dsa : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder

    override fun keyPairGenerator(keySize: BinarySize): KeyGenerator<DSA.KeyPair> =
        DsaKeyPairGenerator(pBits = keySize.inBits.toUInt())

    private object DsaPublicKeyDecoder : Openssl3PublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>("DSA") {
        override fun inputType(format: DSA.PublicKey.Format): String = when (format) {
            DSA.PublicKey.Format.DER -> "DER"
            DSA.PublicKey.Format.PEM -> "PEM"
            DSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PublicKey = DsaPublicKey(key)
    }

    private object DsaPrivateKeyDecoder : Openssl3PrivateKeyDecoder<DSA.PrivateKey.Format, DSA.PrivateKey>("DSA") {
        override fun inputType(format: DSA.PrivateKey.Format): String = when (format) {
            DSA.PrivateKey.Format.DER -> "DER"
            DSA.PrivateKey.Format.PEM -> "PEM"
            DSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): DSA.PrivateKey = DsaPrivateKey(key, publicKey = null)
    }

    private class DsaKeyPairGenerator(
        private val pBits: UInt,
        private val qBits: UInt? = null, // optional; can be set later if needed
    ) : KeyGenerator<DSA.KeyPair> {

        @OptIn(UnsafeNumber::class)
        override fun generateKeyBlocking(): DSA.KeyPair = memScoped {
            // 1) generate DSA parameters
            val paramCtx = checkError(EVP_PKEY_CTX_new_from_name(null, "DSA", null))
            val paramsKey: CPointer<EVP_PKEY> = try {
                checkError(EVP_PKEY_paramgen_init(paramCtx))

                val params = OSSL_PARAM_array(
                    OSSL_PARAM_construct_uint("pbits".cstr.ptr, alloc(pBits).ptr),
                    qBits?.let { OSSL_PARAM_construct_uint("qbits".cstr.ptr, alloc(it).ptr) },
                )
                checkError(EVP_PKEY_CTX_set_params(paramCtx, params))

                val paramsKeyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(paramCtx, paramsKeyVar.ptr))
                checkError(paramsKeyVar.value)
            } finally {
                EVP_PKEY_CTX_free(paramCtx)
            }

            // 2) generate key pair from parameters
            val keyCtx = checkError(EVP_PKEY_CTX_new_from_pkey(null, paramsKey, null))
            try {
                checkError(EVP_PKEY_keygen_init(keyCtx))

                val keyVar = alloc<CPointerVar<EVP_PKEY>>()
                checkError(EVP_PKEY_generate(keyCtx, keyVar.ptr))
                val keyPairKey = checkError(keyVar.value)

                val publicKey = DsaPublicKey(keyPairKey)
                DsaKeyPair(
                    publicKey = publicKey,
                    privateKey = DsaPrivateKey(keyPairKey, publicKey)
                )
            } finally {
                EVP_PKEY_CTX_free(keyCtx)
                EVP_PKEY_free(paramsKey)
            }
        }
    }

    private class DsaKeyPair(
        override val publicKey: DSA.PublicKey,
        override val privateKey: DSA.PrivateKey,
    ) : DSA.KeyPair

    private class DsaPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : DSA.PublicKey, Openssl3PublicKeyEncodable<DSA.PublicKey.Format>(key) {

        override fun outputType(format: DSA.PublicKey.Format): String = when (format) {
            DSA.PublicKey.Format.DER -> "DER"
            DSA.PublicKey.Format.PEM -> "PEM"
            DSA.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureVerifier {
            checkNotNull(digest) { "Pre-hashed (digest=null) DSA is not supported" }

            val derVerifier = DsaDigestSignatureVerifier(key, hashAlgorithmName(digest))

            return when (format) {
                DSA.SignatureFormat.DER -> derVerifier
                DSA.SignatureFormat.RAW -> DsaRawSignatureVerifier(derVerifier, DSA_q_size(key))
            }
        }
    }

    private class DsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: DSA.PublicKey?,
    ) : DSA.PrivateKey,
        Openssl3PrivateKeyEncodable<DSA.PrivateKey.Format, DSA.PublicKey>(key, publicKey) {

        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): DSA.PublicKey = DsaPublicKey(key)

        override fun outputType(format: DSA.PrivateKey.Format): String = when (format) {
            DSA.PrivateKey.Format.DER -> "DER"
            DSA.PrivateKey.Format.PEM -> "PEM"
            DSA.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: DSA.SignatureFormat): SignatureGenerator {
            checkNotNull(digest) { "Pre-hashed (digest=null) DSA is not supported" }

            val derGenerator = DsaDigestSignatureGenerator(key, hashAlgorithmName(digest))

            return when (format) {
                DSA.SignatureFormat.DER -> derGenerator
                DSA.SignatureFormat.RAW -> DsaRawSignatureGenerator(derGenerator, DSA_q_size(key))
            }
        }
    }
}

private class DsaDigestSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class DsaDigestSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

@OptIn(UnsafeNumber::class)
private fun DSA_q_size(key: CPointer<EVP_PKEY>): Int = memScoped {
    val qVar = alloc<CPointerVar<BIGNUM>>()
    checkError(EVP_PKEY_get_bn_param(key, "q", qVar.ptr))
    val q = checkError(qVar.value)
    try {
        (checkError(BN_num_bits(q)) + 7) / 8
    } finally {
        BN_free(q)
    }
}

private class DsaRawSignatureGenerator(
    private val derGenerator: SignatureGenerator,
    private val qSize: Int,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = RawSignFunction(derGenerator.createSignFunction(), qSize)

    private class RawSignFunction(
        private val derSignFunction: SignFunction,
        private val qSize: Int,
    ) : SignFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derSignFunction.update(source, startIndex, endIndex)
        }

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val signature = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
            signature.copyInto(destination, destinationOffset)
            return signature.size
        }

        override fun signToByteArray(): ByteArray {
            val derSignature = derSignFunction.signToByteArray()

            val signatureValue = Der.decodeFromByteArray(DsaSignatureValue.serializer(), derSignature)

            val r = signatureValue.r.encodeToByteArray().trimLeadingZeros()
            val s = signatureValue.s.encodeToByteArray().trimLeadingZeros()

            val rawSignature = ByteArray(qSize * 2)
            r.copyInto(rawSignature, qSize - r.size)
            s.copyInto(rawSignature, qSize * 2 - s.size)
            return rawSignature
        }

        override fun reset() = derSignFunction.reset()
        override fun close() = derSignFunction.close()
    }
}

private class DsaRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val qSize: Int,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = RawVerifyFunction(derVerifier.createVerifyFunction(), qSize)

    private class RawVerifyFunction(
        private val derVerifyFunction: VerifyFunction,
        private val qSize: Int,
    ) : VerifyFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derVerifyFunction.update(source, startIndex, endIndex)
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            check((endIndex - startIndex) == qSize * 2) {
                "Expected signature size ${qSize * 2}, received: ${endIndex - startIndex}"
            }

            val r = signature.copyOfRange(startIndex, startIndex + qSize).makePositive()
            val s = signature.copyOfRange(startIndex + qSize, endIndex).makePositive()

            val signatureValue = DsaSignatureValue(
                r = r.decodeToBigInt(),
                s = s.decodeToBigInt()
            )
            val derSignature = Der.encodeToByteArray(DsaSignatureValue.serializer(), signatureValue)

            return derVerifyFunction.tryVerify(derSignature)
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun reset() = derVerifyFunction.reset()
        override fun close() = derVerifyFunction.close()
    }
}

private fun ByteArray.makePositive(): ByteArray = if (this.isNotEmpty() && this[0] < 0) byteArrayOf(0, *this) else this

private fun ByteArray.trimLeadingZeros(): ByteArray {
    var i = 0
    while (i < size && this[i] == 0.toByte()) i++
    return if (i == 0) this else copyOfRange(i, size)
}
