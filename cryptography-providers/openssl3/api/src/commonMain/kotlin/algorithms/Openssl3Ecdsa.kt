/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Ecdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve): Decoder<EC.PublicKey.Format, ECDSA.PublicKey> = EcPublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EC.Curve): Decoder<EC.PrivateKey.Format, ECDSA.PrivateKey> = EcPrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> = EcKeyGenerator(curve)

    private class EcPrivateKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PrivateKeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey>("EC") {
        override fun inputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW                                -> "DER" // with custom processing
            EC.PrivateKey.Format.JWK                                -> error("JWK format is not supported")
        }

        override fun inputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            EC.PrivateKey.Format.RAW                                     -> "EC" // with custom processing
            else                                                         -> super.inputStruct(format)
        }

        override fun decodeFromByteArrayBlocking(format: EC.PrivateKey.Format, bytes: ByteArray): ECDSA.PrivateKey = when (format) {
            EC.PrivateKey.Format.RAW -> super.decodeFromByteArrayBlocking(format, convertPrivateRawKeyToSec1(curve, bytes))
            else                     -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PrivateKey {
            EC_check_key_group(key, curve)
            return EcPrivateKey(key, publicKey = null)
        }
    }

    private class EcPublicKeyDecoder(
        private val curve: EC.Curve,
    ) : Openssl3PublicKeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey>("EC") {
        override fun inputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
                                    -> error("should not be called: handled explicitly in decodeFromBlocking")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun decodeFromByteArrayBlocking(format: EC.PublicKey.Format, bytes: ByteArray): ECDSA.PublicKey = when (format) {
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
                 -> wrapKey(decodePublicRawKey(curve, bytes))
            else -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PublicKey {
            EC_check_key_group(key, curve)
            return EcPublicKey(key)
        }
    }

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : Openssl3KeyPairGenerator<ECDSA.KeyPair>("EC") {
        @OptIn(UnsafeNumber::class)
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0.convert())
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): ECDSA.KeyPair {
            val publicKey = EcPublicKey(keyPair)
            return EcKeyPair(
                publicKey = publicKey,
                privateKey = EcPrivateKey(keyPair, publicKey)
            )
        }
    }

    private class EcKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcPrivateKey(
        key: CPointer<EVP_PKEY>,
        publicKey: ECDSA.PublicKey?,
    ) : ECDSA.PrivateKey, Openssl3PrivateKeyEncodable<EC.PrivateKey.Format, ECDSA.PublicKey>(key, publicKey) {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): ECDSA.PublicKey = EcPublicKey(key)

        override fun outputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.DER.SEC1 -> "DER"
            EC.PrivateKey.Format.PEM, EC.PrivateKey.Format.PEM.SEC1 -> "PEM"
            EC.PrivateKey.Format.RAW                                -> error("should not be called: handled explicitly in encodeToBlocking")
            EC.PrivateKey.Format.JWK                                -> error("JWK format is not supported")
        }

        override fun outputStruct(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER.SEC1, EC.PrivateKey.Format.PEM.SEC1 -> "EC"
            else                                                         -> super.outputStruct(format)
        }

        override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray = when (format) {
            EC.PrivateKey.Format.RAW -> encodePrivateRawKey(key)
            else                     -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureGenerator {
            val derSignatureGenerator = when (digest) {
                null -> EcdsaPhSignatureGenerator(key)
                else -> EcdsaDigestSignatureGenerator(key, hashAlgorithmName(digest))
            }
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureGenerator
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(derSignatureGenerator, EC_order_size(key))
            }
        }
    }

    private class EcPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDSA.PublicKey, Openssl3PublicKeyEncodable<EC.PublicKey.Format>(key) {
        override fun outputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
                                    -> error("should not be called: handled explicitly in encodeToBlocking")
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray = when (format) {
            EC.PublicKey.Format.RAW            -> encodePublicRawKey(key)
            EC.PublicKey.Format.RAW.Compressed -> encodePublicRawCompressedKey(key)
            else                               -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureVerifier {
            val derSignatureVerifier = when (digest) {
                null -> EcdsaPhSignatureVerifier(key)
                else -> EcdsaDigestSignatureVerifier(key, hashAlgorithmName(digest))
            }
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureVerifier
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(derSignatureVerifier, EC_order_size(key))
            }
        }
    }
}

private class EcdsaPhSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureGenerator(privateKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaDigestSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaRawSignatureGenerator(
    private val derGenerator: SignatureGenerator,
    private val curveOrderSize: Int,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = RawSignFunction(derGenerator.createSignFunction(), curveOrderSize)

    private class RawSignFunction(
        private val derSignFunction: SignFunction,
        private val curveOrderSize: Int,
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

            return memScoped {
                val pdataVar = alloc<CPointerVar<UByteVar>> { value = allocArrayOf(derSignature).reinterpret() }
                val sig = checkError(d2i_ECDSA_SIG(null, pdataVar.ptr, derSignature.size.convert()))
                try {
                    val r = checkError(ECDSA_SIG_get0_r(sig))
                    val s = checkError(ECDSA_SIG_get0_s(sig))
                    val signature = ByteArray(curveOrderSize * 2)
                    checkError(BN_bn2binpad(r, signature.refToU(0), curveOrderSize))
                    checkError(BN_bn2binpad(s, signature.refToU(curveOrderSize), curveOrderSize))
                    signature
                } finally {
                    ECDSA_SIG_free(sig)
                }
            }
        }

        override fun reset() {
            derSignFunction.reset()
        }

        override fun close() {
            derSignFunction.close()
        }
    }
}

private class EcdsaPhSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureVerifier(publicKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaDigestSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaRawSignatureVerifier(
    private val derVerifier: SignatureVerifier,
    private val curveOrderSize: Int,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = RawVerifyFunction(derVerifier.createVerifyFunction(), curveOrderSize)

    private class RawVerifyFunction(
        private val derVerifyFunction: VerifyFunction,
        private val curveOrderSize: Int,
    ) : VerifyFunction {
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            derVerifyFunction.update(source, startIndex, endIndex)
        }

        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            check((endIndex - startIndex) == curveOrderSize * 2) {
                "Expected signature size ${curveOrderSize * 2}, received: ${endIndex - startIndex}"
            }

            val derSignature = memScoped {
                val r = BN_bin2bn(signature.refToU(startIndex), curveOrderSize, null)
                val s = BN_bin2bn(signature.refToU(startIndex + curveOrderSize), curveOrderSize, null)
                val sig = ECDSA_SIG_new()
                try {
                    checkError(ECDSA_SIG_set0(sig, r, s))
                    val outVar = alloc<CPointerVar<UByteVar>>()
                    val signatureLength = checkError(i2d_ECDSA_SIG(sig, outVar.ptr))
                    outVar.value!!.readBytes(signatureLength)
                } finally {
                    ECDSA_SIG_free(sig)
                }
            }

            return derVerifyFunction.tryVerify(derSignature)
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun reset() {
            derVerifyFunction.reset()
        }

        override fun close() {
            derVerifyFunction.close()
        }
    }
}
