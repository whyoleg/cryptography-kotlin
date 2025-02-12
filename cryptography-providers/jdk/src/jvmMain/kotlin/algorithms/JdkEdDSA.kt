package algorithms

import dev.whyoleg.cryptography.operations.SignatureGenerator
import dev.whyoleg.cryptography.operations.SignatureVerifier
import dev.whyoleg.cryptography.providers.jdk.JKeyPair
import dev.whyoleg.cryptography.providers.jdk.JPrivateKey
import dev.whyoleg.cryptography.providers.jdk.JPublicKey
import dev.whyoleg.cryptography.providers.jdk.JdkCryptographyState
import dev.whyoleg.cryptography.providers.jdk.operations.JdkSignatureGenerator
import dev.whyoleg.cryptography.providers.jdk.operations.JdkSignatureVerifier

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
