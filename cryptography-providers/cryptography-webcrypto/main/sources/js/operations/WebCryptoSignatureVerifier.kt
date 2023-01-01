package dev.whyoleg.cryptography.webcrypto.operations

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoSignatureVerifier(
    private val algorithm: VerifyAlgorithm,
    private val key: CryptoKey,
    override val signatureSize: Int,
) : SignatureVerifier {
    override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return WebCrypto.subtle.verify(algorithm, key, signatureInput, dataInput).await()
    }

    override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean = nonBlocking()
}
