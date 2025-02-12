package algorithms

import dev.whyoleg.cryptography.operations.SharedSecretGenerator
import dev.whyoleg.cryptography.providers.jdk.JKeyPair
import dev.whyoleg.cryptography.providers.jdk.JPrivateKey
import dev.whyoleg.cryptography.providers.jdk.JPublicKey
import dev.whyoleg.cryptography.providers.jdk.JdkCryptographyState
import dev.whyoleg.cryptography.providers.jdk.operations.doAgreement

internal class JdkXDH(state: JdkCryptographyState) : JdkEd<XDH.PublicKey, XDH.PrivateKey, XDH.KeyPair>(state), XDH {
    override fun JPublicKey.convert(): XDH.PublicKey = XdhPublicKey(state, this)
    override fun JPrivateKey.convert(): XDH.PrivateKey = XdhPrivateKey(state, this)
    override fun JKeyPair.convert(): XDH.KeyPair = XdhKeyPair(public.convert(), private.convert())

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        private val state: JdkCryptographyState,
        val key: JPublicKey,
    ) : XDH.PublicKey, BaseEdPublicKey(key), SharedSecretGenerator<XDH.PrivateKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }
    }

    private class XdhPrivateKey(
        private val state: JdkCryptographyState,
        val key: JPrivateKey,
    ) : XDH.PrivateKey, BaseEdPrivateKey(key), SharedSecretGenerator<XDH.PublicKey> {
        private val keyAgreement = state.keyAgreement("XDH")
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }
    }
}
