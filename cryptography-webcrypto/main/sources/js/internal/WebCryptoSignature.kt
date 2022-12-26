package dev.whyoleg.cryptography.webcrypto.internal

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoSigner(
    private val algorithm: SignAlgorithm,
    private val key: CryptoKey,
    override val signatureSize: Int,
) : Signer {
    final override suspend fun sign(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.sign(algorithm, key, dataInput).await()
    }

    final override suspend fun sign(dataInput: Buffer, signatureOutput: Buffer): Buffer {
        return sign(dataInput).copyInto(signatureOutput)
    }

    final override fun signBlocking(dataInput: Buffer): Buffer = nonBlocking()
    final override fun signBlocking(dataInput: Buffer, signatureOutput: Buffer): Buffer = nonBlocking()
    final override fun signFunction(): SignFunction = noFunction()
}

internal class WebCryptoVerifier(
    private val algorithm: VerifyAlgorithm,
    private val key: CryptoKey,
    override val signatureSize: Int,
) : Verifier {
    final override suspend fun verify(dataInput: Buffer, signatureInput: Buffer): Boolean {
        return WebCrypto.subtle.verify(algorithm, key, signatureInput, dataInput).await()
    }

    final override fun verifyBlocking(dataInput: Buffer, signatureInput: Buffer): Boolean = nonBlocking()
    final override fun verifyFunction(): VerifyFunction = noFunction()
}
