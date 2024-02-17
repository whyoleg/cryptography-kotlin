/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal object SecRsaPss : SecRsa<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair>(), RSA.PSS {
    override fun hashAlgorithm(digest: CryptographyAlgorithmId<Digest>): SecKeyAlgorithm? = digest.rsaPssSecKeyAlgorithm()

    override fun wrapKeyPair(algorithm: SecKeyAlgorithm?, publicKey: SecKeyRef, privateKey: SecKeyRef): RSA.PSS.KeyPair = RsaPssKeyPair(
        publicKey = RsaPssPublicKey(publicKey, algorithm),
        privateKey = RsaPssPrivateKey(privateKey, algorithm),
    )

    override fun wrapPublicKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PSS.PublicKey = RsaPssPublicKey(key, algorithm)
    override fun wrapPrivateKey(algorithm: SecKeyAlgorithm?, key: SecKeyRef): RSA.PSS.PrivateKey = RsaPssPrivateKey(key, algorithm)

    private class RsaPssKeyPair(
        override val publicKey: RSA.PSS.PublicKey,
        override val privateKey: RSA.PSS.PrivateKey,
    ) : RSA.PSS.KeyPair

    private class RsaPssPublicKey(
        publicKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
    ) : RsaPublicKey(publicKey), RSA.PSS.PublicKey {
        private val verifier = RsaPssSignatureVerifier(publicKey, algorithm)
        override fun signatureVerifier(): SignatureVerifier = verifier
        override fun signatureVerifier(saltLength: BinarySize): SignatureVerifier = error("custom saltLength is not supported")
    }

    private class RsaPssPrivateKey(
        privateKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
    ) : RsaPrivateKey(privateKey), RSA.PSS.PrivateKey {
        private val generator = RsaPssSignatureGenerator(privateKey, algorithm)
        override fun signatureGenerator(): SignatureGenerator = generator
        override fun signatureGenerator(saltLength: BinarySize): SignatureGenerator = error("custom saltLength is not supported")
    }
}

private class RsaPssSignatureGenerator(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureGenerator {
    override fun generateSignatureBlocking(dataInput: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        dataInput.useNSData { data ->
            val signature = SecKeyCreateSignature(
                key = privateKey,
                algorithm = algorithm,
                dataToSign = data.retainBridgeAs<CFDataRef>(),
                error = error.ptr
            )?.releaseBridgeAs<NSData>()

            if (signature == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to generate signature: ${nsError?.description}")
            }

            signature.toByteArray()
        }
    }
}

private class RsaPssSignatureVerifier(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureVerifier {
    override fun verifySignatureBlocking(dataInput: ByteArray, signatureInput: ByteArray): Boolean = memScoped {
        val error = alloc<CFErrorRefVar>()
        dataInput.useNSData { data ->
            signatureInput.useNSData { signature ->
                val result = SecKeyVerifySignature(
                    key = publicKey,
                    algorithm = algorithm,
                    signedData = data.retainBridgeAs<CFDataRef>(),
                    error = error.ptr,
                    signature = signature.retainBridgeAs<CFDataRef>()
                )
                if (!result) {
                    val nsError = error.value.releaseBridgeAs<NSError>()
                    error("Failed to verify signature: ${nsError?.description}")
                }
                result
            }
        }
    }
}
