/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*

internal class JdkRsaPkcs1(
    state: JdkCryptographyState,
) : JdkRsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(state), RSA.PKCS1 {
    override val wrapPublicKey: (JPublicKey, JdkRsaDigest) -> RSA.PKCS1.PublicKey = ::RsaPkcs1PublicKey
    override val wrapPrivateKey: (JPrivateKey, JdkRsaDigest, RSA.PKCS1.PublicKey?) -> RSA.PKCS1.PrivateKey =
        ::RsaPkcs1PrivateKey
    override val wrapKeyPair: (RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey) -> RSA.PKCS1.KeyPair = ::RsaPkcs1KeyPair

    // PKCS1 uses the digest only for signatures, `Signature` named after the digest is resolved when creating signers and verifiers
    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): JdkRsaDigest {
        val _ = state.messageDigest(rsaHashAlgorithmName(digest))
        return JdkRsaDigest(digest, "${digest.hashAlgorithmName()}withRSA")
    }

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private inner class RsaPkcs1PublicKey(
        key: JPublicKey,
        digest: JdkRsaDigest,
    ) : RSA.PKCS1.PublicKey, RsaPublicEncodableKey(key, digest) {
        override fun signatureVerifier(): SignatureVerifier {
            return JdkSignatureVerifier(state, key, digest.name, null)
        }

        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(state, key)
    }

    private inner class RsaPkcs1PrivateKey(
        key: JPrivateKey,
        digest: JdkRsaDigest,
        publicKey: RSA.PKCS1.PublicKey?,
    ) : RSA.PKCS1.PrivateKey, RsaPrivateEncodableKey(key, digest, publicKey) {
        override fun signatureGenerator(): SignatureGenerator {
            return JdkSignatureGenerator(state, key, digest.name, null)
        }

        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(state, key)
    }
}

private class RsaPkcs1Encryptor(
    private val state: JdkCryptographyState,
    private val key: JPublicKey,
) : BaseEncryptor {
    private val cipher = state.cipher("RSA/ECB/PKCS1Padding")

    override fun createEncryptFunction(): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, state.secureRandom)
        })
    }
}

private class RsaPkcs1Decryptor(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
) : BaseDecryptor {
    private val cipher = state.cipher("RSA/ECB/PKCS1Padding")

    override fun createDecryptFunction(): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, state.secureRandom)
        })
    }
}
