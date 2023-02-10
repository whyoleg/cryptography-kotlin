package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.openssl3.materials.*
import dev.whyoleg.cryptography.openssl3.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal object Openssl3Ecdsa : ECDSA {
    override fun publicKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey> = EcPublicKeyDecoder(curve)

    override fun privateKeyDecoder(curve: EC.Curve?): KeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey> = EcPrivateKeyDecoder(curve)

    override fun keyPairGenerator(curve: EC.Curve): KeyGenerator<ECDSA.KeyPair> = EcKeyGenerator(curve)

    private class EcPrivateKeyDecoder(
        private val curve: EC.Curve?,
    ) : Openssl3PrivateKeyDecoder<EC.PrivateKey.Format, ECDSA.PrivateKey>("EC") {
        override fun inputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER -> "DER"
            EC.PrivateKey.Format.PEM -> "PEM"
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        //TODO: validate curve!!!
        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PrivateKey = EcPrivateKey(key)
    }

    private class EcPublicKeyDecoder(
        private val curve: EC.Curve?,
    ) : Openssl3PublicKeyDecoder<EC.PublicKey.Format, ECDSA.PublicKey>("EC") {
        override fun inputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.RAW -> TODO("will be be supported later")
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        //TODO: validate curve!!!
        override fun wrapKey(key: CPointer<EVP_PKEY>): ECDSA.PublicKey = EcPublicKey(key)
    }

    private class EcKeyGenerator(
        private val curve: EC.Curve,
    ) : Openssl3KeyPairGenerator<ECDSA.KeyPair>("EC") {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
            OSSL_PARAM_construct_utf8_string("group".cstr.ptr, curve.name.cstr.ptr, 0)
        )

        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): ECDSA.KeyPair = EcKeyPair(
            publicKey = EcPublicKey(keyPair),
            privateKey = EcPrivateKey(keyPair)
        )
    }

    private class EcKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcPrivateKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDSA.PrivateKey, Openssl3PrivateKeyEncodable<EC.PrivateKey.Format>(key) {
        override fun outputType(format: EC.PrivateKey.Format): String = when (format) {
            EC.PrivateKey.Format.DER -> "DER"
            EC.PrivateKey.Format.PEM -> "PEM"
            EC.PrivateKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureGenerator(key, hashAlgorithm(digest))
        }
    }

    private class EcPublicKey(
        key: CPointer<EVP_PKEY>,
    ) : ECDSA.PublicKey, Openssl3PublicKeyEncodable<EC.PublicKey.Format>(key) {
        override fun outputType(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.RAW -> "BLOB"
            EC.PublicKey.Format.DER -> "DER"
            EC.PublicKey.Format.PEM -> "PEM"
            EC.PublicKey.Format.JWK -> error("JWK format is not supported")
        }

        override fun outputStruct(format: EC.PublicKey.Format): String = when (format) {
            EC.PublicKey.Format.RAW -> "BLOB"
            else                    -> super.outputStruct(format)
        }

        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
            check(format == ECDSA.SignatureFormat.DER) { "Only DER signature format is supported" }
            return EcdsaSignatureVerifier(key, hashAlgorithm(digest))
        }
    }
}

private class EcdsaSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
