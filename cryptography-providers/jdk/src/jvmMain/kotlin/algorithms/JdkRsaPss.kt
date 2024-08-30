/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*

internal class JdkRsaPss(
    private val state: JdkCryptographyState,
) : RSA.PSS {

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PSS.PublicKey> =
        RsaPssPublicKeyDecoder(state, digest.rsaHashAlgorithmName())

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PSS.PrivateKey> =
        RsaPssPrivateKeyDecoder(state, digest.rsaHashAlgorithmName())

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.PSS.KeyPair> {
        val rsaParameters = RSAKeyGenParameterSpec(
            keySize.inBits,
            publicExponent.toJavaBigInteger(),
        )
        return RsaPssKeyPairGenerator(state, rsaParameters, digest.rsaHashAlgorithmName())
    }
}


private class RsaPssPublicKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPublicKeyDecoder<RSA.PSS.PublicKey>(state) {
    override fun JPublicKey.convert(): RSA.PSS.PublicKey = RsaPssPublicKey(state, this, hashAlgorithmName)
}

private class RsaPssPrivateKeyDecoder(
    state: JdkCryptographyState,
    private val hashAlgorithmName: String,
) : RsaPrivateKeyDecoder<RSA.PSS.PrivateKey>(state) {
    override fun JPrivateKey.convert(): RSA.PSS.PrivateKey = RsaPssPrivateKey(state, this, hashAlgorithmName)
}


private class RsaPssKeyPairGenerator(
    state: JdkCryptographyState,
    private val keyGenParameters: RSAKeyGenParameterSpec,
    private val hashAlgorithmName: String,
) : JdkKeyPairGenerator<RSA.PSS.KeyPair>(state, "RSA") {

    override fun JKeyPairGenerator.init() {
        initialize(keyGenParameters, state.secureRandom)
    }

    override fun JKeyPair.convert(): RSA.PSS.KeyPair = RsaPssKeyPair(state, this, hashAlgorithmName)
}

private class RsaPssKeyPair(
    state: JdkCryptographyState,
    keyPair: JKeyPair,
    hashAlgorithmName: String,
) : RSA.PSS.KeyPair {
    override val publicKey: RSA.PSS.PublicKey = RsaPssPublicKey(state, keyPair.public, hashAlgorithmName)
    override val privateKey: RSA.PSS.PrivateKey = RsaPssPrivateKey(state, keyPair.private, hashAlgorithmName)
}

private class RsaPssPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : RSA.PSS.PublicKey, RsaPublicEncodableKey(key) {
    override fun signatureVerifier(): SignatureVerifier {
        val digestSize = state.messageDigest(hashAlgorithmName).use { it.digestLength }
        return signatureVerifier(digestSize.bytes)
    }

    override fun signatureVerifier(saltSize: BinarySize): SignatureVerifier {
        val parameters = PSSParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec(hashAlgorithmName),
            saltSize.inBytes,
            1
        )
        return JdkSignatureVerifier(state, key, "RSASSA-PSS", parameters)
    }
}

private class RsaPssPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : RSA.PSS.PrivateKey, RsaPrivateEncodableKey(key) {
    override fun signatureGenerator(): SignatureGenerator {
        val digestSize = state.messageDigest(hashAlgorithmName).use { it.digestLength }
        return signatureGenerator(digestSize.bytes)
    }

    override fun signatureGenerator(saltSize: BinarySize): SignatureGenerator {
        val parameters = PSSParameterSpec(
            hashAlgorithmName,
            "MGF1",
            MGF1ParameterSpec(hashAlgorithmName),
            saltSize.inBytes,
            1
        )
        return JdkSignatureGenerator(state, key, "RSASSA-PSS", parameters)
    }
}
