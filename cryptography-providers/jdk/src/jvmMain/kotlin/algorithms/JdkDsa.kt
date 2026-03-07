/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.math.*
import java.security.interfaces.*
import java.security.spec.*

internal class JdkDsa(
    private val state: JdkCryptographyState,
) : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder()

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder()

    override fun parametersDecoder(): Decoder<DSA.Parameters.Format, DSA.Parameters> = DsaParametersDecoder()

    override fun parametersGenerator(primeSize: BinarySize, subprimeSize: BinarySize?): ParametersGenerator<DSA.Parameters> =
        DsaParametersGenerator(primeSize, subprimeSize)

    private inner class DsaPublicKeyDecoder :
        JdkPublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>(state, "DSA") {

        fun fromPrivateKey(privateKey: DSAPrivateKey): DSA.PublicKey {
            val params = privateKey.params
            val y = params.g.modPow(privateKey.x, params.p)
            return decode(DSAPublicKeySpec(y, params.p, params.q, params.g))
        }

        override fun decodeFromByteArrayBlocking(format: DSA.PublicKey.Format, bytes: ByteArray): DSA.PublicKey = decodeFromDer(
            when (format) {
                DSA.PublicKey.Format.DER -> bytes
                DSA.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, bytes)
            }
        )

        override fun JPublicKey.convert(): DSA.PublicKey = DsaPublicKey(this)
    }

    private inner class DsaPrivateKeyDecoder :
        JdkPrivateKeyDecoder<DSA.PrivateKey.Format, DSA.PrivateKey>(state, "DSA") {

        override fun decodeFromByteArrayBlocking(format: DSA.PrivateKey.Format, bytes: ByteArray): DSA.PrivateKey = decodeFromDer(
            when (format) {
                DSA.PrivateKey.Format.DER -> bytes
                DSA.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, bytes)
            }
        )

        override fun JPrivateKey.convert(): DSA.PrivateKey {
            check(this is DSAPrivateKey)
            return DsaPrivateKey(this, publicKey = null)
        }
    }

    private inner class DsaParametersDecoder : Decoder<DSA.Parameters.Format, DSA.Parameters> {
        override fun decodeFromByteArrayBlocking(format: DSA.Parameters.Format, bytes: ByteArray): DSA.Parameters = when (format) {
            DSA.Parameters.Format.DER -> decodeFromDer(bytes)
            DSA.Parameters.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.DsaParameters, bytes))
        }

        private fun decodeFromDer(bytes: ByteArray): DSA.Parameters = JdkDsaParameters(
            state.algorithmParameters("DSA").also { it.init(bytes) }
        )
    }

    private inner class DsaParametersGenerator(
        private val primeSize: BinarySize,
        private val subprimeSize: BinarySize?,
    ) : JdkParametersGenerator<DSA.Parameters>(state, "DSA") {
        override fun JAlgorithmParameterGenerator.init() {
            if (subprimeSize != null) {
                // NOTE: DSAGenParameterSpec is not supported by BouncyCastle and Android
                init(DSAGenParameterSpec(primeSize.inBits, subprimeSize.inBits), state.secureRandom)
            } else {
                init(primeSize.inBits, state.secureRandom)
            }
        }

        override fun JAlgorithmParameters.convert(): DSA.Parameters = JdkDsaParameters(this)
    }

    private inner class JdkDsaParameters(
        private val parameters: JAlgorithmParameters,
    ) : DSA.Parameters {
        override fun keyPairGenerator(): KeyGenerator<DSA.KeyPair> {
            return DsaKeyPairGenerator(parameters.getParameterSpec(DSAParameterSpec::class.java))
        }

        override fun encodeToByteArrayBlocking(format: DSA.Parameters.Format): ByteArray = when (format) {
            DSA.Parameters.Format.DER -> parameters.encoded
            DSA.Parameters.Format.PEM -> wrapPem(PemLabel.DsaParameters, parameters.encoded)
        }
    }

    private inner class DsaKeyPairGenerator(
        private val parameters: DSAParameterSpec,
    ) : JdkKeyPairGenerator<DSA.KeyPair>(state, "DSA") {

        override fun JKeyPairGenerator.init() {
            initialize(parameters, state.secureRandom)
        }

        override fun JKeyPair.convert(): DSA.KeyPair {
            val publicKey = DsaPublicKey(public as DSAPublicKey)
            val privateKey = DsaPrivateKey(private as DSAPrivateKey, publicKey)
            return DsaKeyPair(publicKey, privateKey)
        }
    }

    private class DsaKeyPair(
        override val publicKey: DSA.PublicKey,
        override val privateKey: DSA.PrivateKey,
    ) : DSA.KeyPair

    private inner class DsaPublicKey(
        private val key: JPublicKey,
    ) : DSA.PublicKey, JdkEncodableKey<DSA.PublicKey.Format>(key) {

        override fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>?,
            format: DSA.SignatureFormat,
        ): SignatureVerifier {
            val algorithm = digest.dsaSignatureAlgorithmName()
            val verifier = JdkSignatureVerifier(state, key, algorithm, null)

            return when (format) {
                DSA.SignatureFormat.DER -> verifier
                DSA.SignatureFormat.RAW -> DssRawSignatureVerifier(verifier, (key as DSAPublicKey).params.q.byteSize())
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PublicKey.Format): ByteArray = when (format) {
            DSA.PublicKey.Format.DER -> encodeToDer()
            DSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class DsaPrivateKey(
        private val key: DSAPrivateKey,
        private var publicKey: DSA.PublicKey?,
    ) : DSA.PrivateKey, JdkEncodableKey<DSA.PrivateKey.Format>(key) {

        override fun getPublicKeyBlocking(): DSA.PublicKey {
            if (publicKey == null) {
                publicKey = DsaPublicKeyDecoder().fromPrivateKey(key)
            }
            return publicKey!!
        }

        override fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>?,
            format: DSA.SignatureFormat,
        ): SignatureGenerator {
            val algorithm = digest.dsaSignatureAlgorithmName()
            val generator = JdkSignatureGenerator(state, key, algorithm, null)

            return when (format) {
                DSA.SignatureFormat.DER -> generator
                DSA.SignatureFormat.RAW -> DssRawSignatureGenerator(generator, key.params.q.byteSize())
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PrivateKey.Format): ByteArray = when (format) {
            DSA.PrivateKey.Format.DER -> encodeToDer()
            DSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }

}

private fun CryptographyAlgorithmId<Digest>?.dsaSignatureAlgorithmName(): String = when (this) {
    null     -> "NONEwithDSA"
    SHA1     -> "SHA1withDSA"
    SHA224   -> "SHA224withDSA"
    SHA256   -> "SHA256withDSA"
    SHA384   -> "SHA384withDSA"
    SHA512   -> "SHA512withDSA"
    SHA3_224 -> "SHA3-224withDSA"
    SHA3_256 -> "SHA3-256withDSA"
    SHA3_384 -> "SHA3-384withDSA"
    SHA3_512 -> "SHA3-512withDSA"
    else     -> throw IllegalStateException("Unsupported hash algorithm for DSA: $this")
}

private fun BigInteger.byteSize(): Int = (bitLength() + 7) / 8
