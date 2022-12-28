package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoSignatureGenerator(
    private val algorithm: SignAlgorithm,
    private val key: CryptoKey,
    override val signatureSize: Int,
) : SignatureGenerator {
    final override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.sign(algorithm, key, dataInput).await()
    }

    final override suspend fun generateSignature(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        return generateSignature(dataInput).copyInto(signatureOutput)
    }

    final override fun generateSignatureBlocking(dataInput: Buffer): Buffer = nonBlocking()
    final override fun generateSignatureBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer = nonBlocking()
}

internal class WebCryptoSignatureVerifier(
    private val algorithm: VerifyAlgorithm,
    private val key: CryptoKey,
    override val signatureSize: Int,
) : SignatureVerifier {
    final override suspend fun verifySignature(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return WebCrypto.subtle.verify(algorithm, key, signatureInput, dataInput).await()
    }

    final override fun verifySignatureBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean = nonBlocking()
}
