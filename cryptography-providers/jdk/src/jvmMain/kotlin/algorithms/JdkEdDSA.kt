package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.EdDSA
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

internal class JdkEdDSA(state: JdkCryptographyState) : JdkEd<EdDSA.PublicKey, EdDSA.PrivateKey, EdDSA.KeyPair>(state), EdDSA {
    override fun JPublicKey.convert(): EdDSA.PublicKey = EdDsaPublicKey(state, this)
    override fun JPrivateKey.convert(): EdDSA.PrivateKey = EdDsaPrivateKey(state, this)
    override fun JKeyPair.convert(): EdDSA.KeyPair = EdDsaKeyPair(public.convert(), private.convert())

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        private val state: JdkCryptographyState,
        private val key: JPublicKey,
    ) : EdDSA.PublicKey, BaseEdPublicKey(key) {
        override fun signatureVerifier(): SignatureVerifier {
            return JdkSignatureVerifier(state, key, "EdDSA", null)
        }
    }

    private class EdDsaPrivateKey(
        private val state: JdkCryptographyState,
        private val key: JPrivateKey,
    ) : EdDSA.PrivateKey, BaseEdPrivateKey(key) {
        override fun signatureGenerator(): SignatureGenerator {
            return JdkSignatureGenerator(state, key, "EdDSA", null)
        }
    }
}
