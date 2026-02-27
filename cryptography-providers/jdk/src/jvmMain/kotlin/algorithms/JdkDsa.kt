/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.unwrapPem
import dev.whyoleg.cryptography.providers.base.materials.wrapPem
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.pem.*
import java.math.BigInteger
import java.security.interfaces.*
import java.security.spec.*

internal class JdkDsa(
    private val state: JdkCryptographyState,
) : DSA {

    override fun publicKeyDecoder(): Decoder<DSA.PublicKey.Format, DSA.PublicKey> = DsaPublicKeyDecoder()

    override fun privateKeyDecoder(): Decoder<DSA.PrivateKey.Format, DSA.PrivateKey> = DsaPrivateKeyDecoder()

    override fun keyPairGenerator(keySize: BinarySize): KeyGenerator<DSA.KeyPair> = DsaKeyPairGenerator(keySize)

    private inner class DsaPublicKeyDecoder :
        JdkPublicKeyDecoder<DSA.PublicKey.Format, DSA.PublicKey>(state, "DSA") {

        override fun decodeFromByteArrayBlocking(format: DSA.PublicKey.Format, bytes: ByteArray): DSA.PublicKey = decodeFromDer(
            when (format) {
                DSA.PublicKey.Format.JWK -> error("$format is not supported")
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
                DSA.PrivateKey.Format.JWK -> error("$format is not supported")
                DSA.PrivateKey.Format.DER -> bytes
                DSA.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, bytes)
            }
        )

        override fun JPrivateKey.convert(): DSA.PrivateKey = DsaPrivateKey(this, publicKey = null)
    }

    private inner class DsaKeyPairGenerator(
        private val keySize: BinarySize,
    ) : JdkKeyPairGenerator<DSA.KeyPair>(state, "DSA") {

        override fun JKeyPairGenerator.init() {
            initialize(keySize.inBits, state.secureRandom)
        }

        override fun JKeyPair.convert(): DSA.KeyPair {
            val publicKey = DsaPublicKey(public)
            val privateKey = DsaPrivateKey(private, publicKey)
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
                DSA.SignatureFormat.RAW -> error("$format is not supported by JDK DSA implementation")
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PublicKey.Format): ByteArray = when (format) {
            DSA.PublicKey.Format.JWK -> error("$format is not supported")
            DSA.PublicKey.Format.DER -> encodeToDer()
            DSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }
    }

    private inner class DsaPrivateKey(
        private val key: JPrivateKey,
        private var publicKey: DSA.PublicKey?,
    ) : DSA.PrivateKey, JdkEncodableKey<DSA.PrivateKey.Format>(key) {

        override fun getPublicKeyBlocking(): DSA.PublicKey {
            if (publicKey == null) {
                publicKey = derivePublicKeyFromPrivate(key)
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
                DSA.SignatureFormat.RAW -> error("$format is not supported by JDK DSA implementation")
            }
        }

        override fun encodeToByteArrayBlocking(format: DSA.PrivateKey.Format): ByteArray = when (format) {
            DSA.PrivateKey.Format.JWK -> error("$format is not supported")
            DSA.PrivateKey.Format.DER -> encodeToDer()
            DSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }
    }

    private fun derivePublicKeyFromPrivate(privateKey: JPrivateKey): DSA.PublicKey {
        val dsaPrivateKey = privateKey as? DSAPrivateKey
            ?: error("Expected DSAPrivateKey, got: ${privateKey::class.qualifiedName}")

        val params = dsaPrivateKey.params
        val p = params.p
        val g = params.g
        val x = dsaPrivateKey.x

        val y: BigInteger = g.modPow(x, p)

        val spec = DSAPublicKeySpec(y, params.p, params.q, params.g)
        val factory = state.keyFactory("DSA")
        val jPublic = factory.use { it.generatePublic(spec) } as JPublicKey
        return DsaPublicKey(jPublic)
    }
}

private fun CryptographyAlgorithmId<Digest>?.dsaSignatureAlgorithmName(): String = when (this) {
    null -> "NONEwithDSA"
    SHA1 -> "SHA1withDSA"
    SHA224 -> "SHA224withDSA"
    SHA256 -> "SHA256withDSA"
    SHA384 -> "SHA384withDSA"
    SHA512 -> "SHA512withDSA"
    else -> throw IllegalStateException("Unsupported hash algorithm for DSA: $this")
}
