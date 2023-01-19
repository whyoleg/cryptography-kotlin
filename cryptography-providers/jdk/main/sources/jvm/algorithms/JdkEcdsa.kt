package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.jdk.operations.*
import dev.whyoleg.cryptography.operations.signature.*

internal class JdkEcdsa(state: JdkCryptographyState) : JdkEc<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(state), ECDSA {
    override fun JPublicKey.convert(): ECDSA.PublicKey = EcdsaPublicKey(state, this)
    override fun JPrivateKey.convert(): ECDSA.PrivateKey = EcdsaPrivateKey(state, this)
    override fun JKeyPair.convert(): ECDSA.KeyPair = EcdsaKeyPair(public.convert(), private.convert())
}

private class EcdsaKeyPair(
    override val publicKey: ECDSA.PublicKey,
    override val privateKey: ECDSA.PrivateKey,
) : ECDSA.KeyPair

private class EcdsaPublicKey(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : ECDSA.PublicKey, JdkEncodableKey<EC.PublicKey.Format>(key, "EC") {
    override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>): SignatureVerifier {
        return JdkSignatureVerifier(state, key, digest.hashAlgorithmName() + "withECDSA", null)
    }
}

private class EcdsaPrivateKey(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : ECDSA.PrivateKey, JdkEncodableKey<EC.PrivateKey.Format>(key, "EC") {
    override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>): SignatureGenerator {
        return JdkSignatureGenerator(state, key, digest.hashAlgorithmName() + "withECDSA", null)
    }
}
