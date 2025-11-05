/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import java.security.spec.*
import javax.crypto.spec.*

internal class JdkRsaOaep(
    state: JdkCryptographyState,
) : JdkRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(state), RSA.OAEP {
    override val wrapPublicKey: (JPublicKey, String) -> RSA.OAEP.PublicKey = ::RsaOaepPublicKey
    override val wrapPrivateKey: (JPrivateKey, String, RSA.OAEP.PublicKey?) -> RSA.OAEP.PrivateKey = ::RsaOaepPrivateKey
    override val wrapKeyPair: (RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey) -> RSA.OAEP.KeyPair = ::RsaOaepKeyPair

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private inner class RsaOaepPublicKey(
        key: JPublicKey,
        private val hashAlgorithmName: String,
    ) : RSA.OAEP.PublicKey, RsaPublicEncodableKey(key) {
        override fun encryptor(): AuthenticatedEncryptor = RsaOaepEncryptor(state, key, hashAlgorithmName)
    }

    private inner class RsaOaepPrivateKey(
        key: JPrivateKey,
        hashAlgorithmName: String,
        publicKey: RSA.OAEP.PublicKey?,
    ) : RSA.OAEP.PrivateKey, RsaPrivateEncodableKey(key, hashAlgorithmName, publicKey) {
        override fun decryptor(): AuthenticatedDecryptor = RsaOaepDecryptor(state, key, hashAlgorithmName)
    }
}

private class RsaOaepEncryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
    private val hashAlgorithmName: String,
) : BaseAuthenticatedEncryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            val parameters = OAEPParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
            )
            init(JCipher.ENCRYPT_MODE, key, parameters, state.secureRandom)
        })
    }
}

private class RsaOaepDecryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val hashAlgorithmName: String,
) : BaseAuthenticatedDecryptor {
    private val cipher = state.cipher("RSA/ECB/OAEPPadding")

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            val parameters = OAEPParameterSpec(
                hashAlgorithmName,
                "MGF1",
                MGF1ParameterSpec(hashAlgorithmName),
                associatedData?.let(PSource::PSpecified) ?: PSource.PSpecified.DEFAULT
            )
            init(JCipher.DECRYPT_MODE, key, parameters, state.secureRandom)
        })
    }
}
